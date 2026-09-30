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
	"slices"
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
	created.Bindings = CanonicalizeGlobalBindings(created.GetBindings())
	f.policy = created
	return proto.Clone(created).(*ateapipb.AccessPolicy), nil
}

func (f *fakeGlobalPolicyStore) UpdateGlobalAccessPolicy(_ context.Context, pre store.Precondition, mutate func(*ateapipb.AccessPolicy) error) (*ateapipb.AccessPolicy, error) {
	if f.policy == nil {
		return nil, store.ErrNotFound
	}
	if err := pre.Check(f.policy.GetMetadata()); err != nil {
		return nil, err
	}
	updated := proto.Clone(f.policy).(*ateapipb.AccessPolicy)
	if err := mutate(updated); err != nil {
		return nil, err
	}
	updated.Bindings = CanonicalizeGlobalBindings(updated.GetBindings())
	updated.Metadata.Version++
	f.policy = updated
	return proto.Clone(updated).(*ateapipb.AccessPolicy), nil
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

	// 3. Re-bootstrapping with an existing owner is a no-op and does not bump version.
	if err := pm.BootstrapGlobalOwners(ctx, s, []string{"carol"}); err != nil {
		t.Fatalf("BootstrapGlobalOwners(carol) repeat failed: %v", err)
	}
	if got := s.policy.GetMetadata().GetVersion(); got != 1 {
		t.Errorf("version after repeat bootstrap = %d, want 1", got)
	}

	// 4. Bootstrapping an additional owner merges into bindings and bumps version to 2.
	if err := pm.BootstrapGlobalOwners(ctx, s, []string{"dave"}); err != nil {
		t.Fatalf("BootstrapGlobalOwners(dave) failed: %v", err)
	}
	if got := s.policy.GetMetadata().GetVersion(); got != 2 {
		t.Errorf("version after adding dave = %d, want 2", got)
	}
	var owners []string
	for _, b := range s.policy.GetBindings() {
		if b.GetRole() == RoleOwner {
			owners = b.GetMembers()
		}
	}
	if !slices.Contains(owners, "user:carol") || !slices.Contains(owners, "user:dave") {
		t.Errorf("global owners = %v, want user:carol and user:dave", owners)
	}
}
