// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controlapi

import (
	"context"
	"strings"
	"testing"

	"github.com/agent-substrate/substrate/cmd/ateapi/internal/authz"
	"github.com/agent-substrate/substrate/cmd/ateapi/internal/store/storetest"
	"github.com/agent-substrate/substrate/internal/principal"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestAccessPolicy_GlobalAndAtespaceGovernance(t *testing.T) {
	persistence := storetest.SetupPostgresPersistence(t)
	ctx := context.Background()

	pool := persistence.Pool()
	fgaServer, err := authz.NewOpenFGAServer(pool)
	if err != nil {
		t.Fatalf("NewOpenFGAServer failed: %v", err)
	}
	t.Cleanup(fgaServer.Close)

	authorizer, policyManager, err := authz.New(ctx, pool, fgaServer)
	if err != nil {
		t.Fatalf("authz.New failed: %v", err)
	}
	persistence.SetPolicyManager(policyManager)

	// Bootstrap alice@example.com as initial global owner.
	if err := policyManager.BootstrapGlobalOwners(ctx, persistence, []string{"alice@example.com"}); err != nil {
		t.Fatalf("BootstrapGlobalOwners failed: %v", err)
	}

	svc := NewRPCService(persistence, nil, nil, nil, nil, nil, nil, "", nil, nil, "", nil, nil)
	interceptor := authz.UnaryServerInterceptor(authorizer)

	userCtx := func(id string) context.Context {
		return principal.InjectContext(ctx, principal.PrincipalInfo{
			ID:   id,
			Kind: principal.KindJWT,
		})
	}
	aliceCtx := userCtx("alice@example.com")
	bobCtx := userCtx("bob@example.com")
	charlieCtx := userCtx("charlie@example.com")

	invoke := func(c context.Context, method string, req any, handler func(context.Context, any) (any, error)) (any, error) {
		return interceptor(c, req, &grpc.UnaryServerInfo{FullMethod: method}, handler)
	}

	// 1. GetGlobalAccessPolicy: Alice (global owner) succeeds; Bob (unprivileged) is denied.
	if _, err := invoke(bobCtx, ateapipb.Control_GetGlobalAccessPolicy_FullMethodName, &ateapipb.GetGlobalAccessPolicyRequest{}, func(c context.Context, r any) (any, error) {
		return svc.GetGlobalAccessPolicy(c, r.(*ateapipb.GetGlobalAccessPolicyRequest))
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied for Bob on GetGlobalAccessPolicy, got %v", err)
	}

	globalPolAny, err := invoke(aliceCtx, ateapipb.Control_GetGlobalAccessPolicy_FullMethodName, &ateapipb.GetGlobalAccessPolicyRequest{}, func(c context.Context, r any) (any, error) {
		return svc.GetGlobalAccessPolicy(c, r.(*ateapipb.GetGlobalAccessPolicyRequest))
	})
	if err != nil {
		t.Fatalf("GetGlobalAccessPolicy as Alice failed: %v", err)
	}
	globalPol := globalPolAny.(*ateapipb.AccessPolicy)
	if globalPol.GetMetadata().GetName() != "default" || globalPol.GetMetadata().GetVersion() != 1 {
		t.Fatalf("unexpected initial global policy metadata: %+v", globalPol.GetMetadata())
	}

	// CreateGlobalAccessPolicy when already bootstrapped returns AlreadyExists.
	createGlobalReq := &ateapipb.CreateGlobalAccessPolicyRequest{
		AccessPolicy: &ateapipb.AccessPolicy{
			Metadata: &ateapipb.ResourceMetadata{Name: "default"},
			Bindings: []*ateapipb.Binding{
				{Role: authz.RoleOwner, Members: []string{"user:alice@example.com"}},
			},
		},
	}
	if _, err := invoke(aliceCtx, ateapipb.Control_CreateGlobalAccessPolicy_FullMethodName, createGlobalReq, func(c context.Context, r any) (any, error) {
		return svc.CreateGlobalAccessPolicy(c, r.(*ateapipb.CreateGlobalAccessPolicyRequest))
	}); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("expected AlreadyExists on CreateGlobalAccessPolicy when already bootstrapped, got %v", err)
	}

	// 2. Anti-lockout: Alice cannot remove herself or leave zero owners on GlobalAccessPolicy.
	noOwnerReq := &ateapipb.UpdateGlobalAccessPolicyRequest{
		AccessPolicy: &ateapipb.AccessPolicy{
			Metadata: globalPol.GetMetadata(),
			Bindings: []*ateapipb.Binding{
				{Role: authz.RoleViewer, Members: []string{"user:bob@example.com"}},
			},
		},
	}
	if _, err := invoke(aliceCtx, ateapipb.Control_UpdateGlobalAccessPolicy_FullMethodName, noOwnerReq, func(c context.Context, r any) (any, error) {
		return svc.UpdateGlobalAccessPolicy(c, r.(*ateapipb.UpdateGlobalAccessPolicyRequest))
	}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument when removing all global owners, got %v", err)
	}

	selfLockoutReq := &ateapipb.UpdateGlobalAccessPolicyRequest{
		AccessPolicy: &ateapipb.AccessPolicy{
			Metadata: globalPol.GetMetadata(),
			Bindings: []*ateapipb.Binding{
				{Role: authz.RoleOwner, Members: []string{"user:bob@example.com"}},
			},
		},
	}
	if _, err := invoke(aliceCtx, ateapipb.Control_UpdateGlobalAccessPolicy_FullMethodName, selfLockoutReq, func(c context.Context, r any) (any, error) {
		return svc.UpdateGlobalAccessPolicy(c, r.(*ateapipb.UpdateGlobalAccessPolicyRequest))
	}); status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "cannot remove themselves") {
		t.Fatalf("expected self-lockout InvalidArgument error, got %v", err)
	}

	// 3. UpdateGlobalAccessPolicy: Alice grants Bob global viewer; version increments to 2.
	updateGlobalReq := &ateapipb.UpdateGlobalAccessPolicyRequest{
		AccessPolicy: &ateapipb.AccessPolicy{
			Metadata: globalPol.GetMetadata(),
			Bindings: []*ateapipb.Binding{
				{Role: authz.RoleOwner, Members: []string{"user:alice@example.com"}},
				{Role: authz.RoleViewer, Members: []string{"user:bob@example.com"}},
			},
		},
	}
	updatedGlobalAny, err := invoke(aliceCtx, ateapipb.Control_UpdateGlobalAccessPolicy_FullMethodName, updateGlobalReq, func(c context.Context, r any) (any, error) {
		return svc.UpdateGlobalAccessPolicy(c, r.(*ateapipb.UpdateGlobalAccessPolicyRequest))
	})
	if err != nil {
		t.Fatalf("UpdateGlobalAccessPolicy failed: %v", err)
	}
	updatedGlobal := updatedGlobalAny.(*ateapipb.AccessPolicy)
	if updatedGlobal.GetMetadata().GetVersion() != 2 {
		t.Fatalf("expected global policy version 2, got %d", updatedGlobal.GetMetadata().GetVersion())
	}

	// Stale version 1 write must fail with Aborted.
	if _, err := invoke(aliceCtx, ateapipb.Control_UpdateGlobalAccessPolicy_FullMethodName, updateGlobalReq, func(c context.Context, r any) (any, error) {
		return svc.UpdateGlobalAccessPolicy(c, r.(*ateapipb.UpdateGlobalAccessPolicyRequest))
	}); status.Code(err) != codes.Aborted {
		t.Fatalf("expected Aborted for stale version on UpdateGlobalAccessPolicy, got %v", err)
	}

	// Bob (now global viewer) can call GetGlobalAccessPolicy (`can_get_access_policy`),
	// but is still denied UpdateGlobalAccessPolicy (`can_update_access_policy`).
	if _, err := invoke(bobCtx, ateapipb.Control_GetGlobalAccessPolicy_FullMethodName, &ateapipb.GetGlobalAccessPolicyRequest{}, func(c context.Context, r any) (any, error) {
		return svc.GetGlobalAccessPolicy(c, r.(*ateapipb.GetGlobalAccessPolicyRequest))
	}); err != nil {
		t.Fatalf("expected Bob (global viewer) to be allowed GetGlobalAccessPolicy, got %v", err)
	}
	if _, err := invoke(bobCtx, ateapipb.Control_UpdateGlobalAccessPolicy_FullMethodName, updateGlobalReq, func(c context.Context, r any) (any, error) {
		return svc.UpdateGlobalAccessPolicy(c, r.(*ateapipb.UpdateGlobalAccessPolicyRequest))
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected Bob (global viewer) to be denied UpdateGlobalAccessPolicy, got %v", err)
	}

	// 4. CreateAtespace does not automatically create an AccessPolicy row;
	// GetAtespaceAccessPolicy returns NotFound until CreateAtespaceAccessPolicy is called.
	createSpaceReq := &ateapipb.CreateAtespaceRequest{
		Atespace: &ateapipb.Atespace{
			Metadata: &ateapipb.ResourceMetadata{Name: "team-alpha"},
		},
	}
	if _, err := invoke(aliceCtx, ateapipb.Control_CreateAtespace_FullMethodName, createSpaceReq, func(c context.Context, r any) (any, error) {
		return svc.CreateAtespace(c, r.(*ateapipb.CreateAtespaceRequest))
	}); err != nil {
		t.Fatalf("CreateAtespace(team-alpha) failed: %v", err)
	}

	getSpacePolReq := &ateapipb.GetAtespaceAccessPolicyRequest{
		Atespace: &ateapipb.ObjectRef{Name: "team-alpha"},
	}
	if _, err := invoke(aliceCtx, ateapipb.Control_GetAtespaceAccessPolicy_FullMethodName, getSpacePolReq, func(c context.Context, r any) (any, error) {
		return svc.GetAtespaceAccessPolicy(c, r.(*ateapipb.GetAtespaceAccessPolicyRequest))
	}); status.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound before CreateAtespaceAccessPolicy, got %v", err)
	}

	// 5. CreateAtespaceAccessPolicy: Alice creates team-alpha's policy granting Charlie editor.
	createSpacePolReq := &ateapipb.CreateAtespaceAccessPolicyRequest{
		Atespace: &ateapipb.ObjectRef{Name: "team-alpha"},
		AccessPolicy: &ateapipb.AccessPolicy{
			Metadata: &ateapipb.ResourceMetadata{Name: "default"},
			Bindings: []*ateapipb.Binding{
				{Role: authz.RoleOwner, Members: []string{"user:alice@example.com"}},
				{Role: authz.RoleEditor, Members: []string{"user:charlie@example.com"}},
			},
		},
	}
	createdSpacePolAny, err := invoke(aliceCtx, ateapipb.Control_CreateAtespaceAccessPolicy_FullMethodName, createSpacePolReq, func(c context.Context, r any) (any, error) {
		return svc.CreateAtespaceAccessPolicy(c, r.(*ateapipb.CreateAtespaceAccessPolicyRequest))
	})
	if err != nil {
		t.Fatalf("CreateAtespaceAccessPolicy(team-alpha) failed: %v", err)
	}
	createdSpacePol := createdSpacePolAny.(*ateapipb.AccessPolicy)
	if createdSpacePol.GetMetadata().GetVersion() != 1 {
		t.Fatalf("expected Atespace policy version 1, got %d", createdSpacePol.GetMetadata().GetVersion())
	}

	// Charlie (editor on team-alpha) can GetAtespaceAccessPolicy (`can_get_access_policy`),
	// but is denied UpdateAtespaceAccessPolicy (`can_update_access_policy` requires owner)
	// and DeleteAtespaceAccessPolicy (`can_delete_access_policy` requires owner).
	if _, err := invoke(charlieCtx, ateapipb.Control_GetAtespaceAccessPolicy_FullMethodName, getSpacePolReq, func(c context.Context, r any) (any, error) {
		return svc.GetAtespaceAccessPolicy(c, r.(*ateapipb.GetAtespaceAccessPolicyRequest))
	}); err != nil {
		t.Fatalf("expected Charlie (atespace editor) allowed GetAtespaceAccessPolicy, got %v", err)
	}
	updateSpacePolReq := &ateapipb.UpdateAtespaceAccessPolicyRequest{
		Atespace: &ateapipb.ObjectRef{Name: "team-alpha"},
		AccessPolicy: &ateapipb.AccessPolicy{
			Metadata: createdSpacePol.GetMetadata(),
			Bindings: []*ateapipb.Binding{
				{Role: authz.RoleOwner, Members: []string{"user:alice@example.com"}},
				{Role: authz.RoleViewer, Members: []string{"user:charlie@example.com"}},
			},
		},
	}
	if _, err := invoke(charlieCtx, ateapipb.Control_UpdateAtespaceAccessPolicy_FullMethodName, updateSpacePolReq, func(c context.Context, r any) (any, error) {
		return svc.UpdateAtespaceAccessPolicy(c, r.(*ateapipb.UpdateAtespaceAccessPolicyRequest))
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected Charlie (atespace editor) denied UpdateAtespaceAccessPolicy, got %v", err)
	}
	deleteSpacePolReq := &ateapipb.DeleteAtespaceAccessPolicyRequest{
		Atespace: &ateapipb.ObjectRef{Name: "team-alpha"},
	}
	if _, err := invoke(charlieCtx, ateapipb.Control_DeleteAtespaceAccessPolicy_FullMethodName, deleteSpacePolReq, func(c context.Context, r any) (any, error) {
		return svc.DeleteAtespaceAccessPolicy(c, r.(*ateapipb.DeleteAtespaceAccessPolicyRequest))
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected Charlie (atespace editor) denied DeleteAtespaceAccessPolicy, got %v", err)
	}

	// 6. UpdateAtespaceAccessPolicy as Alice succeeds and bumps version to 2.
	updatedSpacePolAny, err := invoke(aliceCtx, ateapipb.Control_UpdateAtespaceAccessPolicy_FullMethodName, updateSpacePolReq, func(c context.Context, r any) (any, error) {
		return svc.UpdateAtespaceAccessPolicy(c, r.(*ateapipb.UpdateAtespaceAccessPolicyRequest))
	})
	if err != nil {
		t.Fatalf("UpdateAtespaceAccessPolicy(team-alpha) failed: %v", err)
	}
	updatedSpacePol := updatedSpacePolAny.(*ateapipb.AccessPolicy)
	if updatedSpacePol.GetMetadata().GetVersion() != 2 {
		t.Fatalf("expected Atespace policy version 2, got %d", updatedSpacePol.GetMetadata().GetVersion())
	}

	// 7. DeleteAtespaceAccessPolicy removes both the policy row and OpenFGA tuples.
	if _, err := invoke(aliceCtx, ateapipb.Control_DeleteAtespaceAccessPolicy_FullMethodName, deleteSpacePolReq, func(c context.Context, r any) (any, error) {
		return svc.DeleteAtespaceAccessPolicy(c, r.(*ateapipb.DeleteAtespaceAccessPolicyRequest))
	}); err != nil {
		t.Fatalf("DeleteAtespaceAccessPolicy(team-alpha) failed: %v", err)
	}
	// Charlie's tuple on team-alpha was removed, so Charlie can no longer GetAtespaceAccessPolicy.
	if _, err := invoke(charlieCtx, ateapipb.Control_GetAtespaceAccessPolicy_FullMethodName, getSpacePolReq, func(c context.Context, r any) (any, error) {
		return svc.GetAtespaceAccessPolicy(c, r.(*ateapipb.GetAtespaceAccessPolicyRequest))
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected Charlie denied after DeleteAtespaceAccessPolicy, got %v", err)
	}

	// 8. Recreate team-alpha's AccessPolicy; it gets a new UID, so an Update carrying
	// the old UID fails with Aborted (UID conflict).
	recreatedPolAny, err := invoke(aliceCtx, ateapipb.Control_CreateAtespaceAccessPolicy_FullMethodName, createSpacePolReq, func(c context.Context, r any) (any, error) {
		return svc.CreateAtespaceAccessPolicy(c, r.(*ateapipb.CreateAtespaceAccessPolicyRequest))
	})
	if err != nil {
		t.Fatalf("re-creating team-alpha access policy failed: %v", err)
	}
	recreatedPol := recreatedPolAny.(*ateapipb.AccessPolicy)
	if recreatedPol.GetMetadata().GetUid() == createdSpacePol.GetMetadata().GetUid() {
		t.Fatalf("expected new UID on recreated access policy, got same UID %s", recreatedPol.GetMetadata().GetUid())
	}
	if _, err := invoke(aliceCtx, ateapipb.Control_UpdateAtespaceAccessPolicy_FullMethodName, updateSpacePolReq, func(c context.Context, r any) (any, error) {
		return svc.UpdateAtespaceAccessPolicy(c, r.(*ateapipb.UpdateAtespaceAccessPolicyRequest))
	}); status.Code(err) != codes.Aborted || !strings.Contains(err.Error(), "UID conflict") {
		t.Fatalf("expected Aborted UID conflict for UpdateAtespaceAccessPolicy with old UID, got %v", err)
	}
}
