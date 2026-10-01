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
	"errors"
	"fmt"
	"slices"

	"github.com/agent-substrate/substrate/cmd/ateapi/internal/authz"
	"github.com/agent-substrate/substrate/cmd/ateapi/internal/defaults"
	"github.com/agent-substrate/substrate/cmd/ateapi/internal/store"
	"github.com/agent-substrate/substrate/internal/principal"
	"github.com/agent-substrate/substrate/internal/resources"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"k8s.io/apimachinery/pkg/api/operation"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

var (
	validGlobalRoles   = []string{authz.RoleOwner, authz.RoleViewer}
	validAtespaceRoles = []string{authz.RoleOwner, authz.RoleEditor, authz.RoleViewer}
)

func (s *RPCService) GetGlobalAccessPolicy(ctx context.Context, req *ateapipb.GetGlobalAccessPolicyRequest) (*ateapipb.AccessPolicy, error) {
	if errs := validateGetGlobalAccessPolicyRequest(ctx, req); len(errs) > 0 {
		return nil, resources.ToGRPCStatusError(errs)
	}
	return s.impl.GetGlobalAccessPolicy(ctx)
}

func (s *ServiceImpl) GetGlobalAccessPolicy(ctx context.Context) (*ateapipb.AccessPolicy, error) {
	policy, err := s.store.GetGlobalAccessPolicy(ctx)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "Global AccessPolicy not found")
		}
		return nil, fmt.Errorf("while getting Global access policy: %w", err)
	}
	return policy, nil
}

func validateGetGlobalAccessPolicyRequest(_ context.Context, _ *ateapipb.GetGlobalAccessPolicyRequest) field.ErrorList {
	return nil
}

func (s *RPCService) UpdateGlobalAccessPolicy(ctx context.Context, req *ateapipb.UpdateGlobalAccessPolicyRequest) (*ateapipb.AccessPolicy, error) {
	policy := req.GetAccessPolicy()
	if policy != nil {
		scrubResourceMetadataForUpdate(policy.Metadata)
	}
	if errs := validateUpdateGlobalAccessPolicyRequest(ctx, req); len(errs) > 0 {
		return nil, resources.ToGRPCStatusError(errs)
	}
	return s.impl.UpdateGlobalAccessPolicy(ctx, store.PreconditionFrom(policy), replaceAccessPolicy(policy))
}

func (s *ServiceImpl) UpdateGlobalAccessPolicy(ctx context.Context, precondition store.Precondition, mutate func(*ateapipb.AccessPolicy) error) (*ateapipb.AccessPolicy, error) {
	updated, err := s.store.UpdateGlobalAccessPolicy(ctx, precondition, func(toUpdate *ateapipb.AccessPolicy) error {
		oldVal := proto.Clone(toUpdate).(*ateapipb.AccessPolicy)
		if err := mutate(toUpdate); err != nil {
			return err
		}
		errs := validateAccessPolicyUpdate(ctx, field.NewPath("access_policy"), toUpdate, oldVal)
		errs = append(errs, validateGlobalPolicyRules(ctx, field.NewPath("access_policy", "bindings"), toUpdate)...)
		if len(errs) > 0 {
			return resources.ToGRPCStatusError(errs)
		}
		return nil
	})
	return mapAccessPolicyWrite(updated, err)
}

func validateUpdateGlobalAccessPolicyRequest(ctx context.Context, req *ateapipb.UpdateGlobalAccessPolicyRequest) field.ErrorList {
	errs := Validate_UpdateGlobalAccessPolicyRequest(ctx, operation.Operation{Type: operation.Create}, nil, req, nil)
	return append(errs, validateGlobalPolicyRules(ctx, field.NewPath("access_policy", "bindings"), req.GetAccessPolicy())...)
}

func (s *RPCService) CreateAtespaceAccessPolicy(ctx context.Context, req *ateapipb.CreateAtespaceAccessPolicyRequest) (*ateapipb.AccessPolicy, error) {
	policy := req.GetAccessPolicy()
	if policy != nil {
		scrubResourceMetadataForCreate(policy.Metadata)
		defaults.Apply(policy)
	}
	if errs := validateCreateAtespaceAccessPolicyRequest(ctx, req); len(errs) > 0 {
		return nil, resources.ToGRPCStatusError(errs)
	}
	return s.impl.CreateAtespaceAccessPolicy(ctx, req.GetAtespace().GetName(), policy)
}

func (s *ServiceImpl) CreateAtespaceAccessPolicy(ctx context.Context, name string, policy *ateapipb.AccessPolicy) (*ateapipb.AccessPolicy, error) {
	created, err := s.store.CreateAtespaceAccessPolicy(ctx, name, policy)
	return mapAccessPolicyWrite(created, err)
}

func validateCreateAtespaceAccessPolicyRequest(ctx context.Context, req *ateapipb.CreateAtespaceAccessPolicyRequest) field.ErrorList {
	errs := Validate_CreateAtespaceAccessPolicyRequest(ctx, operation.Operation{Type: operation.Create}, nil, req, nil)
	return append(errs, validateAccessPolicyBindings(field.NewPath("access_policy", "bindings"), req.GetAccessPolicy(), validAtespaceRoles)...)
}

func (s *RPCService) GetAtespaceAccessPolicy(ctx context.Context, req *ateapipb.GetAtespaceAccessPolicyRequest) (*ateapipb.AccessPolicy, error) {
	if errs := validateGetAtespaceAccessPolicyRequest(ctx, req); len(errs) > 0 {
		return nil, resources.ToGRPCStatusError(errs)
	}
	return s.impl.GetAtespaceAccessPolicy(ctx, req.GetAtespace().GetName())
}

func (s *ServiceImpl) GetAtespaceAccessPolicy(ctx context.Context, name string) (*ateapipb.AccessPolicy, error) {
	policy, err := s.store.GetAtespaceAccessPolicy(ctx, name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "AccessPolicy for atespace %s not found", name)
		}
		return nil, fmt.Errorf("while getting Atespace access policy: %w", err)
	}
	return policy, nil
}

func validateGetAtespaceAccessPolicyRequest(ctx context.Context, req *ateapipb.GetAtespaceAccessPolicyRequest) field.ErrorList {
	return Validate_GetAtespaceAccessPolicyRequest(ctx, operation.Operation{Type: operation.Create}, nil, req, nil)
}

func (s *RPCService) UpdateAtespaceAccessPolicy(ctx context.Context, req *ateapipb.UpdateAtespaceAccessPolicyRequest) (*ateapipb.AccessPolicy, error) {
	policy := req.GetAccessPolicy()
	if policy != nil {
		scrubResourceMetadataForUpdate(policy.Metadata)
	}
	if errs := validateUpdateAtespaceAccessPolicyRequest(ctx, req); len(errs) > 0 {
		return nil, resources.ToGRPCStatusError(errs)
	}
	return s.impl.UpdateAtespaceAccessPolicy(ctx, req.GetAtespace().GetName(), store.PreconditionFrom(policy), replaceAccessPolicy(policy))
}

func (s *ServiceImpl) UpdateAtespaceAccessPolicy(ctx context.Context, name string, precondition store.Precondition, mutate func(*ateapipb.AccessPolicy) error) (*ateapipb.AccessPolicy, error) {
	updated, err := s.store.UpdateAtespaceAccessPolicy(ctx, name, precondition, func(toUpdate *ateapipb.AccessPolicy) error {
		oldVal := proto.Clone(toUpdate).(*ateapipb.AccessPolicy)
		if err := mutate(toUpdate); err != nil {
			return err
		}
		errs := validateAccessPolicyUpdate(ctx, field.NewPath("access_policy"), toUpdate, oldVal)
		errs = append(errs, validateAccessPolicyBindings(field.NewPath("access_policy", "bindings"), toUpdate, validAtespaceRoles)...)
		if len(errs) > 0 {
			return resources.ToGRPCStatusError(errs)
		}
		return nil
	})
	return mapAccessPolicyWrite(updated, err)
}

func validateUpdateAtespaceAccessPolicyRequest(ctx context.Context, req *ateapipb.UpdateAtespaceAccessPolicyRequest) field.ErrorList {
	errs := Validate_UpdateAtespaceAccessPolicyRequest(ctx, operation.Operation{Type: operation.Create}, nil, req, nil)
	return append(errs, validateAccessPolicyBindings(field.NewPath("access_policy", "bindings"), req.GetAccessPolicy(), validAtespaceRoles)...)
}

func validateAccessPolicyUpdate(ctx context.Context, p *field.Path, newVal, oldVal *ateapipb.AccessPolicy) field.ErrorList {
	return Validate_AccessPolicy(ctx, operation.Operation{Type: operation.Update}, p, newVal, oldVal)
}

func (s *RPCService) DeleteAtespaceAccessPolicy(ctx context.Context, req *ateapipb.DeleteAtespaceAccessPolicyRequest) (*ateapipb.AccessPolicy, error) {
	if errs := validateDeleteAtespaceAccessPolicyRequest(ctx, req); len(errs) > 0 {
		return nil, resources.ToGRPCStatusError(errs)
	}
	return s.impl.DeleteAtespaceAccessPolicy(ctx, req.GetAtespace().GetName(), toDeletePreconditions(req.GetOptions()))
}

func (s *ServiceImpl) DeleteAtespaceAccessPolicy(ctx context.Context, name string, precondition store.DeletePreconditions) (*ateapipb.AccessPolicy, error) {
	deleted, err := s.store.DeleteAtespaceAccessPolicy(ctx, name, precondition)
	return mapAccessPolicyWrite(deleted, err)
}

func validateDeleteAtespaceAccessPolicyRequest(ctx context.Context, req *ateapipb.DeleteAtespaceAccessPolicyRequest) field.ErrorList {
	return Validate_DeleteAtespaceAccessPolicyRequest(ctx, operation.Operation{Type: operation.Create}, nil, req, nil)
}

func replaceAccessPolicy(policy *ateapipb.AccessPolicy) func(*ateapipb.AccessPolicy) error {
	return func(toUpdate *ateapipb.AccessPolicy) error {
		metadata := toUpdate.GetMetadata()
		proto.Reset(toUpdate)
		proto.Merge(toUpdate, policy)
		toUpdate.Metadata = metadata
		defaults.Apply(toUpdate)
		return nil
	}
}

func ValidateCustom_AccessPolicy_Metadata(_ context.Context, _ operation.Operation, root *field.Path, meta, _ *ateapipb.ResourceMetadata) field.ErrorList {
	if meta == nil {
		return nil
	}
	var errs field.ErrorList
	if meta.Atespace != "" {
		errs = append(errs, field.Forbidden(root.Child("atespace"), "must not be set"))
	}
	if meta.Name != "" && meta.Name != "default" {
		errs = append(errs, field.Invalid(root.Child("name"), meta.Name, `must be "default"`).WithOrigin("custom=default"))
	}
	return errs
}

const maxMembersPerPolicy = 1500

func validateGlobalPolicyRules(ctx context.Context, bindingsPath *field.Path, policy *ateapipb.AccessPolicy) field.ErrorList {
	errs := validateAccessPolicyBindings(bindingsPath, policy, validGlobalRoles)
	return append(errs, validateGlobalOwnersRetained(ctx, bindingsPath, policy)...)
}

func validateAccessPolicyBindings(bindingsPath *field.Path, policy *ateapipb.AccessPolicy, allowedRoles []string) field.ErrorList {
	if policy == nil {
		return nil
	}
	var errs field.ErrorList
	seenRoles := make(map[string]bool, len(policy.GetBindings()))
	totalMembers := 0
	for i, b := range policy.GetBindings() {
		if b == nil {
			continue
		}
		bp := bindingsPath.Index(i)
		role := b.GetRole()
		if role != "" {
			if !slices.Contains(allowedRoles, role) {
				errs = append(errs, field.NotSupported(bp.Child("role"), role, allowedRoles))
			} else if seenRoles[role] {
				errs = append(errs, field.Duplicate(bp.Child("role"), role))
			}
			seenRoles[role] = true
		}
		membersPath := bp.Child("members")
		totalMembers += len(b.GetMembers())
		for j, member := range b.GetMembers() {
			if _, err := authz.FormatMember(member); err != nil {
				errs = append(errs, field.Invalid(membersPath.Index(j), member, err.Error()))
			}
		}
	}
	if totalMembers > maxMembersPerPolicy {
		errs = append(errs, field.TooMany(bindingsPath, totalMembers, maxMembersPerPolicy))
	}
	return errs
}

func validateGlobalOwnersRetained(ctx context.Context, bindingsPath *field.Path, policy *ateapipb.AccessPolicy) field.ErrorList {
	if policy == nil {
		return nil
	}
	var ownerMembers []string
	for _, b := range policy.GetBindings() {
		if b != nil && b.GetRole() == authz.RoleOwner {
			ownerMembers = append(ownerMembers, b.GetMembers()...)
		}
	}
	if len(ownerMembers) == 0 {
		return field.ErrorList{
			field.Required(bindingsPath, "global access policy must retain at least one owner"),
		}
	}
	if !authz.IsBypassed(ctx) {
		if p, ok := principal.FromContext(ctx); ok && p.ID != "" {
			callerMember := "user:" + p.ID
			if !slices.Contains(ownerMembers, callerMember) {
				return field.ErrorList{
					field.Forbidden(bindingsPath, fmt.Sprintf("caller %q cannot remove themselves from the global owner role", callerMember)),
				}
			}
		}
	}
	return nil
}

func mapAccessPolicyWrite(policy *ateapipb.AccessPolicy, err error) (*ateapipb.AccessPolicy, error) {
	switch {
	case err == nil:
		return policy, nil
	case errors.Is(err, store.ErrNotFound):
		return nil, status.Error(codes.NotFound, "AccessPolicy not found")
	case errors.Is(err, store.ErrAlreadyExists):
		return nil, status.Error(codes.AlreadyExists, "AccessPolicy already exists")
	case errors.Is(err, store.ErrVersionConflict):
		return nil, status.Error(codes.Aborted, "AccessPolicy version conflict")
	case errors.Is(err, store.ErrUIDConflict):
		return nil, status.Error(codes.Aborted, "AccessPolicy UID conflict")
	case errors.Is(err, store.ErrPreconditionRequired):
		return nil, status.Error(codes.InvalidArgument, "AccessPolicy UID and version are required")
	case errors.Is(err, store.ErrFailedPrecondition):
		return nil, status.Error(codes.FailedPrecondition, "parent Atespace does not exist")
	default:
		return nil, fmt.Errorf("while writing AccessPolicy: %w", err)
	}
}
