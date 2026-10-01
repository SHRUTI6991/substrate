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
	"errors"
	"fmt"
	"strings"

	"github.com/agent-substrate/substrate/cmd/ateapi/internal/store"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"github.com/jackc/pgx/v5"
	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/openfga/openfga/pkg/server"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// ErrNilTransaction is returned by PolicyManager tuple writes called without a
// PostgreSQL transaction.
var ErrNilTransaction = errors.New("authz: policy tuple writes require a non-nil pgx.Tx")

// GlobalPolicyStore is the persistence interface used by BootstrapGlobalOwners.
type GlobalPolicyStore interface {
	GetGlobalAccessPolicy(ctx context.Context) (*ateapipb.AccessPolicy, error)
	CreateGlobalAccessPolicy(ctx context.Context, policy *ateapipb.AccessPolicy) (*ateapipb.AccessPolicy, error)
}

// PolicyManager manages authorization tuple writes, global owner bootstrapping,
// and lifecycle cleanup in OpenFGA.
type PolicyManager struct {
	fgaServer *server.Server
	storeID   string
	modelID   string
}

// BootstrapGlobalOwners seeds the initial global access policy with ownerIDs
// as owners on global:root when no global access policy exists yet. If a
// global access policy with at least one owner already exists, it immediately
// returns nil without modifying the stored policy.
func (m *PolicyManager) BootstrapGlobalOwners(ctx context.Context, s GlobalPolicyStore, ownerIDs []string) error {
	if m == nil || s == nil {
		return fmt.Errorf("policy manager and store must not be nil")
	}

	var members []string
	for _, id := range ownerIDs {
		if clean := strings.TrimSpace(id); clean != "" {
			member := "user:" + strings.TrimPrefix(clean, "user:")
			if _, err := FormatMember(member); err != nil {
				return fmt.Errorf("invalid bootstrap owner %q: %w", id, err)
			}
			members = append(members, member)
		}
	}

	const maxAttempts = 5
	for attempt := range maxAttempts {
		err := bootstrapGlobalOwnersOnce(ctx, s, members)
		if err == nil {
			return nil
		}
		if attempt < maxAttempts-1 && errors.Is(err, store.ErrAlreadyExists) {
			continue
		}
		return err
	}
	return nil
}

func bootstrapGlobalOwnersOnce(ctx context.Context, s GlobalPolicyStore, members []string) error {
	existing, err := s.GetGlobalAccessPolicy(ctx)
	if errors.Is(err, store.ErrNotFound) {
		if len(members) == 0 {
			return fmt.Errorf("at least one bootstrap owner ID is required when global policy has no owners")
		}
		_, err := s.CreateGlobalAccessPolicy(ctx, &ateapipb.AccessPolicy{
			Bindings: []*ateapipb.Binding{{Role: RoleOwner, Members: members}},
		})
		return err
	}
	if err != nil {
		return fmt.Errorf("getting global access policy: %w", err)
	}

	for _, b := range existing.GetBindings() {
		if b.GetRole() == RoleOwner && len(b.GetMembers()) > 0 {
			return nil
		}
	}
	return fmt.Errorf("at least one bootstrap owner ID is required when global policy has no owners")
}

// ReconcileGlobalBindings reconciles the OpenFGA role bindings on global:root
// within tx. The tuple changes commit or roll back with tx.
func (m *PolicyManager) ReconcileGlobalBindings(ctx context.Context, tx pgx.Tx, bindings []*ateapipb.Binding) error {
	return m.reconcileBindings(ctx, tx, GlobalRootObject, bindings)
}

// ReconcileAtespaceBindings reconciles the OpenFGA role bindings on an atespace
// within tx. The tuple changes commit or roll back with tx.
func (m *PolicyManager) ReconcileAtespaceBindings(ctx context.Context, tx pgx.Tx, name string, bindings []*ateapipb.Binding) error {
	return m.reconcileBindings(ctx, tx, AtespaceObject(name), bindings)
}

// DeleteAtespacePolicies removes all OpenFGA tuples associated with an atespace
// within tx. The tuple deletions commit or roll back with tx.
func (m *PolicyManager) DeleteAtespacePolicies(ctx context.Context, tx pgx.Tx, name string) error {
	return m.reconcileBindings(ctx, tx, AtespaceObject(name), nil)
}

func (m *PolicyManager) applyMutationsChunked(ctx context.Context, toWrite []*openfgav1.TupleKey, toDelete []*openfgav1.TupleKeyWithoutCondition) error {
	for i := 0; i < len(toDelete); i += maxTuplesPerWrite {
		end := min(i+maxTuplesPerWrite, len(toDelete))
		if _, err := m.fgaServer.Write(ctx, &openfgav1.WriteRequest{
			StoreId:              m.storeID,
			AuthorizationModelId: m.modelID,
			Deletes: &openfgav1.WriteRequestDeletes{
				TupleKeys: toDelete[i:end],
				OnMissing: "ignore",
			},
		}); err != nil {
			return err
		}
	}
	for i := 0; i < len(toWrite); i += maxTuplesPerWrite {
		end := min(i+maxTuplesPerWrite, len(toWrite))
		if _, err := m.fgaServer.Write(ctx, &openfgav1.WriteRequest{
			StoreId:              m.storeID,
			AuthorizationModelId: m.modelID,
			Writes: &openfgav1.WriteRequestWrites{
				TupleKeys:   toWrite[i:end],
				OnDuplicate: "ignore",
			},
		}); err != nil {
			return err
		}
	}
	return nil
}

func (m *PolicyManager) readObjectTuples(ctx context.Context, obj string) ([]*openfgav1.TupleKey, error) {
	var out []*openfgav1.TupleKey
	var contToken string
	for {
		readResp, err := m.fgaServer.Read(ctx, &openfgav1.ReadRequest{
			StoreId:           m.storeID,
			TupleKey:          &openfgav1.ReadRequestTupleKey{Object: obj},
			PageSize:          wrapperspb.Int32(maxTuplesPerWrite),
			ContinuationToken: contToken,
		})
		if err != nil {
			return nil, err
		}
		for _, t := range readResp.GetTuples() {
			if tk := t.GetKey(); tk != nil {
				out = append(out, tk)
			}
		}
		if readResp.GetContinuationToken() == "" {
			break
		}
		contToken = readResp.GetContinuationToken()
	}
	return out, nil
}

// reconcileBindings diffs the existing OpenFGA tuples on obj against
// desiredBindings and writes only the net additions and deletions in batches
// within tx, leaving unchanged (relation, user) tuples untouched.
func (m *PolicyManager) reconcileBindings(ctx context.Context, tx pgx.Tx, obj string, desiredBindings []*ateapipb.Binding) error {
	if tx == nil {
		return ErrNilTransaction
	}
	// The OpenFGA server API only carries ctx, so the transactional datastore
	// reads tx back out of it.
	ctx = ContextWithTx(ctx, tx)

	existingTuples, err := m.readObjectTuples(ctx, obj)
	if err != nil {
		return fmt.Errorf("reading existing tuples for %q: %w", obj, err)
	}

	type relUser struct {
		relation string
		user     string
	}
	existingSet := make(map[relUser]struct{}, len(existingTuples))
	for _, tk := range existingTuples {
		existingSet[relUser{relation: tk.GetRelation(), user: tk.GetUser()}] = struct{}{}
	}

	var toWrite []*openfgav1.TupleKey
	desiredSet := make(map[relUser]struct{}, len(desiredBindings)*2)
	for _, b := range desiredBindings {
		role := b.GetRole()
		for _, rawMember := range b.GetMembers() {
			fgaUser, err := FormatMember(rawMember)
			if err != nil {
				return err
			}
			ru := relUser{relation: role, user: fgaUser}
			if _, alreadyDesired := desiredSet[ru]; alreadyDesired {
				continue
			}
			desiredSet[ru] = struct{}{}
			if _, exists := existingSet[ru]; !exists {
				toWrite = append(toWrite, &openfgav1.TupleKey{
					User:     ru.user,
					Relation: ru.relation,
					Object:   obj,
				})
			} else {
				delete(existingSet, ru)
			}
		}
	}

	var toDelete []*openfgav1.TupleKeyWithoutCondition
	for ru := range existingSet {
		toDelete = append(toDelete, &openfgav1.TupleKeyWithoutCondition{
			User:     ru.user,
			Relation: ru.relation,
			Object:   obj,
		})
	}

	if err := m.applyMutationsChunked(ctx, toWrite, toDelete); err != nil {
		return fmt.Errorf("reconciling policy tuples on %q: %w", obj, err)
	}
	return nil
}
