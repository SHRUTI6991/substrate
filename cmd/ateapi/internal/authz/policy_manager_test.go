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

package authz

import (
	"context"
	"testing"

	"github.com/agent-substrate/substrate/cmd/ateapi/internal/store"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
)

type fakeGlobalPolicyStore struct {
	policy *ateapipb.AccessPolicy
}

func (f *fakeGlobalPolicyStore) GetGlobalAccessPolicy(_ context.Context) (*ateapipb.AccessPolicy, error) {
	if f.policy == nil {
		return nil, store.ErrNotFound
	}
	return proto.Clone(f.policy).(*ateapipb.AccessPolicy), nil
}

func (f *fakeGlobalPolicyStore) CreateGlobalAccessPolicy(_ context.Context, policy *ateapipb.AccessPolicy) (*ateapipb.AccessPolicy, error) {
	if f.policy != nil {
		return nil, store.ErrAlreadyExists
	}
	created := proto.Clone(policy).(*ateapipb.AccessPolicy)
	created.Metadata = &ateapipb.ResourceMetadata{Name: "default", Uid: "uid-1", Version: 1}
	f.policy = created
	return proto.Clone(created).(*ateapipb.AccessPolicy), nil
}

func TestBootstrapGlobalOwners(t *testing.T) {
	ctx := t.Context()
	pm := &PolicyManager{}
	s := &fakeGlobalPolicyStore{}

	// 1. Empty bootstrap owners before global policy exists fails.
	if err := pm.BootstrapGlobalOwners(ctx, s, nil); err == nil {
		t.Fatal("expected error when bootstrapping with no owners and no existing policy")
	}

	// 2. First bootstrap creates the global policy at version 1.
	if err := pm.BootstrapGlobalOwners(ctx, s, []string{"carol"}); err != nil {
		t.Fatalf("BootstrapGlobalOwners(carol) failed: %v", err)
	}
	if got := s.policy.GetMetadata().GetVersion(); got != 1 {
		t.Errorf("version after initial bootstrap = %d, want 1", got)
	}
	wantBindings := []*ateapipb.Binding{{Role: RoleOwner, Members: []string{"user:carol"}}}
	if diff := cmp.Diff(wantBindings, s.policy.GetBindings(), protocmp.Transform()); diff != "" {
		t.Errorf("bindings after initial bootstrap (-want +got):\n%s", diff)
	}

	// 3. Re-bootstrapping with an existing owner, a different owner, or no owners
	// is a no-op once a global policy with at least one owner exists.
	for _, owners := range [][]string{{"carol"}, {"dave"}, nil} {
		if err := pm.BootstrapGlobalOwners(ctx, s, owners); err != nil {
			t.Fatalf("BootstrapGlobalOwners(%v) repeat failed: %v", owners, err)
		}
		if got := s.policy.GetMetadata().GetVersion(); got != 1 {
			t.Errorf("version after BootstrapGlobalOwners(%v) = %d, want 1", owners, got)
		}
		if diff := cmp.Diff(wantBindings, s.policy.GetBindings(), protocmp.Transform()); diff != "" {
			t.Errorf("bindings after BootstrapGlobalOwners(%v) (-want +got):\n%s", owners, diff)
		}
	}
}
