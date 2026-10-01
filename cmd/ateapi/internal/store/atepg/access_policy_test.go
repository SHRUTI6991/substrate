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

package atepg

import (
	"errors"
	"testing"

	"github.com/agent-substrate/substrate/cmd/ateapi/internal/authz"
	"github.com/agent-substrate/substrate/cmd/ateapi/internal/store"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/testing/protocmp"
)

// setupPostgresPersistenceWithAuthz returns a store with an OpenFGA-backed
// PolicyManager, which access policy operations require.
func setupPostgresPersistenceWithAuthz(t *testing.T) *Persistence {
	t.Helper()
	p := setupPostgresPersistence(t)
	fgaServer, err := authz.NewOpenFGAServer(p.pool)
	if err != nil {
		t.Fatalf("NewOpenFGAServer failed: %v", err)
	}
	t.Cleanup(fgaServer.Close)
	_, policyManager, err := authz.New(t.Context(), p.pool, fgaServer)
	if err != nil {
		t.Fatalf("authz.New failed: %v", err)
	}
	p.SetPolicyManager(policyManager)
	return p
}

func TestAccessPolicy_AuthzDisabled(t *testing.T) {
	p := setupPostgresPersistence(t)
	ctx := t.Context()
	createTestAtespace(t, p, "team-a")
	policy := &ateapipb.AccessPolicy{
		Bindings: []*ateapipb.Binding{{Role: authz.RoleOwner, Members: []string{"user:alice"}}},
	}
	noop := func(*ateapipb.AccessPolicy) error { return nil }
	pre := store.Precondition{UID: "uid", Version: 1}

	ops := map[string]func() error{
		"CreateGlobalAccessPolicy": func() error { _, err := p.CreateGlobalAccessPolicy(ctx, policy); return err },
		"GetGlobalAccessPolicy":    func() error { _, err := p.GetGlobalAccessPolicy(ctx); return err },
		"UpdateGlobalAccessPolicy": func() error { _, err := p.UpdateGlobalAccessPolicy(ctx, pre, noop); return err },
		"CreateAtespaceAccessPolicy": func() error {
			_, err := p.CreateAtespaceAccessPolicy(ctx, "team-a", policy)
			return err
		},
		"GetAtespaceAccessPolicy": func() error { _, err := p.GetAtespaceAccessPolicy(ctx, "team-a"); return err },
		"UpdateAtespaceAccessPolicy": func() error {
			_, err := p.UpdateAtespaceAccessPolicy(ctx, "team-a", pre, noop)
			return err
		},
		"DeleteAtespaceAccessPolicy": func() error {
			_, err := p.DeleteAtespaceAccessPolicy(ctx, "team-a", store.DeletePreconditions{})
			return err
		},
	}
	for name, op := range ops {
		if err := op(); !errors.Is(err, store.ErrAuthzDisabled) {
			t.Errorf("%s without a policy manager = %v, want ErrAuthzDisabled", name, err)
		}
	}

	// Nothing was written, so no policy row exists to drift from the tuples.
	var n int
	if err := p.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM global_access_policy) + (SELECT count(*) FROM atespace_access_policies)`).Scan(&n); err != nil {
		t.Fatalf("counting access policy rows: %v", err)
	}
	if n != 0 {
		t.Errorf("access policy rows = %d, want 0", n)
	}

	// Atespaces stay deletable with authorization disabled.
	if _, err := p.DeleteAtespace(ctx, "team-a", store.DeletePreconditions{}); err != nil {
		t.Errorf("DeleteAtespace without a policy manager failed: %v", err)
	}
}

func TestGlobalAccessPolicy_Lifecycle(t *testing.T) {
	p := setupPostgresPersistenceWithAuthz(t)
	ctx := t.Context()

	if _, err := p.GetGlobalAccessPolicy(ctx); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetGlobalAccessPolicy before create = %v, want ErrNotFound", err)
	}

	policy := &ateapipb.AccessPolicy{
		Bindings: []*ateapipb.Binding{
			{Role: authz.RoleViewer, Members: []string{"user:bob"}},
			{Role: authz.RoleOwner, Members: []string{"user:alice"}},
		},
	}
	created, err := p.CreateGlobalAccessPolicy(ctx, policy)
	if err != nil {
		t.Fatalf("CreateGlobalAccessPolicy failed: %v", err)
	}
	if created.GetMetadata().GetName() != "default" || created.GetMetadata().GetVersion() != 1 || created.GetMetadata().GetUid() == "" {
		t.Fatalf("unexpected created metadata: %+v", created.GetMetadata())
	}
	if diff := cmp.Diff(policy.GetBindings(), created.GetBindings(), protocmp.Transform()); diff != "" {
		t.Errorf("created bindings (-want +got):\n%s", diff)
	}

	if _, err := p.CreateGlobalAccessPolicy(ctx, policy); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("second CreateGlobalAccessPolicy = %v, want ErrAlreadyExists", err)
	}

	got, err := p.GetGlobalAccessPolicy(ctx)
	if err != nil || !cmp.Equal(got, created, protocmp.Transform()) {
		t.Fatalf("GetGlobalAccessPolicy = %v, %v; want %v", got, err, created)
	}

	if _, err := p.UpdateGlobalAccessPolicy(ctx, store.Precondition{}, func(*ateapipb.AccessPolicy) error { return nil }); !errors.Is(err, store.ErrPreconditionRequired) {
		t.Fatalf("UpdateGlobalAccessPolicy without precondition = %v, want ErrPreconditionRequired", err)
	}
	if _, err := p.UpdateGlobalAccessPolicy(ctx, store.Precondition{UID: created.GetMetadata().GetUid(), Version: 99}, func(*ateapipb.AccessPolicy) error { return nil }); !errors.Is(err, store.ErrVersionConflict) {
		t.Fatalf("UpdateGlobalAccessPolicy wrong version = %v, want ErrVersionConflict", err)
	}
	if _, err := p.UpdateGlobalAccessPolicy(ctx, store.Precondition{UID: "wrong-uid", Version: 1}, func(*ateapipb.AccessPolicy) error { return nil }); !errors.Is(err, store.ErrUIDConflict) {
		t.Fatalf("UpdateGlobalAccessPolicy wrong uid = %v, want ErrUIDConflict", err)
	}

	updated, err := p.UpdateGlobalAccessPolicy(ctx, store.PreconditionFrom(created), func(toUpdate *ateapipb.AccessPolicy) error {
		toUpdate.Bindings = []*ateapipb.Binding{
			{Role: authz.RoleOwner, Members: []string{"user:alice", "user:carol"}},
		}
		return nil
	})
	if err != nil || updated.GetMetadata().GetVersion() != 2 {
		t.Fatalf("UpdateGlobalAccessPolicy = %v, %v; want version 2", updated, err)
	}
}

func TestAtespaceAccessPolicy_LifecycleAndCascade(t *testing.T) {
	p := setupPostgresPersistenceWithAuthz(t)
	ctx := t.Context()

	policy := &ateapipb.AccessPolicy{
		Bindings: []*ateapipb.Binding{
			{Role: authz.RoleEditor, Members: []string{"user:bob"}},
		},
	}
	if _, err := p.CreateAtespaceAccessPolicy(ctx, "missing-space", policy); !errors.Is(err, store.ErrFailedPrecondition) {
		t.Fatalf("CreateAtespaceAccessPolicy on missing atespace = %v, want ErrFailedPrecondition", err)
	}

	if _, err := p.CreateAtespace(ctx, newTestAtespace("team-a")); err != nil {
		t.Fatalf("CreateAtespace failed: %v", err)
	}
	if _, err := p.GetAtespaceAccessPolicy(ctx, "team-a"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetAtespaceAccessPolicy before create = %v, want ErrNotFound", err)
	}

	created, err := p.CreateAtespaceAccessPolicy(ctx, "team-a", policy)
	if err != nil {
		t.Fatalf("CreateAtespaceAccessPolicy failed: %v", err)
	}
	if _, err := p.CreateAtespaceAccessPolicy(ctx, "team-a", policy); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("second CreateAtespaceAccessPolicy = %v, want ErrAlreadyExists", err)
	}

	updated, err := p.UpdateAtespaceAccessPolicy(ctx, "team-a", store.PreconditionFrom(created), func(toUpdate *ateapipb.AccessPolicy) error {
		toUpdate.Bindings = []*ateapipb.Binding{
			{Role: authz.RoleViewer, Members: []string{"user:dave"}},
		}
		return nil
	})
	if err != nil || updated.GetMetadata().GetVersion() != 2 {
		t.Fatalf("UpdateAtespaceAccessPolicy = %v, %v; want version 2", updated, err)
	}

	if _, err := p.DeleteAtespaceAccessPolicy(ctx, "team-a", store.DeletePreconditions{Version: 99}); !errors.Is(err, store.ErrVersionConflict) {
		t.Fatalf("DeleteAtespaceAccessPolicy wrong version = %v, want ErrVersionConflict", err)
	}
	if _, err := p.DeleteAtespaceAccessPolicy(ctx, "team-a", store.DeletePreconditions{UID: "wrong-uid"}); !errors.Is(err, store.ErrUIDConflict) {
		t.Fatalf("DeleteAtespaceAccessPolicy wrong uid = %v, want ErrUIDConflict", err)
	}

	deleted, err := p.DeleteAtespaceAccessPolicy(ctx, "team-a", store.DeletePreconditions{
		UID:     updated.GetMetadata().GetUid(),
		Version: updated.GetMetadata().GetVersion(),
	})
	if err != nil || !cmp.Equal(deleted, updated, protocmp.Transform()) {
		t.Fatalf("DeleteAtespaceAccessPolicy = %v, %v; want %v", deleted, err, updated)
	}
	if _, err := p.GetAtespaceAccessPolicy(ctx, "team-a"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetAtespaceAccessPolicy after delete = %v, want ErrNotFound", err)
	}

	// Recreate policy and verify DeleteAtespace cascades to atespace_access_policies.
	if _, err := p.CreateAtespaceAccessPolicy(ctx, "team-a", policy); err != nil {
		t.Fatalf("re-creating access policy failed: %v", err)
	}
	if _, err := p.DeleteAtespace(ctx, "team-a", store.DeletePreconditions{}); err != nil {
		t.Fatalf("DeleteAtespace failed: %v", err)
	}
	if _, err := p.GetAtespaceAccessPolicy(ctx, "team-a"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetAtespaceAccessPolicy after DeleteAtespace = %v, want ErrNotFound", err)
	}
}
