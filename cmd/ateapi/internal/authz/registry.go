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
	"slices"

	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// check is one OpenFGA permission check: the caller must have relation on object.
type check struct {
	relation string
	object   string
}

// checkExtractor returns the checks a request must pass; the interceptor allows
// the request only if all of them pass. A check whose resource identifier is
// missing from a malformed request is left out, so the handler's field
// validation returns codes.InvalidArgument for it. If no checks remain, the
// interceptor verifies caller authentication and delegates to the handler.
// If err is non-nil (e.g., unexpected request protobuf type), the interceptor fails closed.
type checkExtractor func(req any) ([]check, error)

// checksOf adapts checksFor, written against the concrete request type T, into
// a checkExtractor.
func checksOf[T any](checksFor func(T) []check) checkExtractor {
	return func(req any) ([]check, error) {
		r, ok := req.(T)
		if !ok {
			return nil, status.Errorf(codes.Internal, "authz: unexpected request type %T", req)
		}
		return checksFor(r), nil
	}
}

func onGlobal(relation string) []check {
	return []check{{relation: relation, object: GlobalRootObject}}
}

func onAtespace(relation, atespace string) []check {
	if atespace == "" {
		return nil
	}
	return []check{{relation: relation, object: AtespaceObject(atespace)}}
}

// onAtespaceOrGlobal checks relation on the atespace, or on global:root when
// atespace is empty (List RPCs that span all atespaces).
func onAtespaceOrGlobal(relation, atespace string) []check {
	if atespace == "" {
		return onGlobal(relation)
	}
	return onAtespace(relation, atespace)
}

// resourceRef identifies an atespaced resource. Both *ateapipb.ObjectRef and
// *ateapipb.ResourceMetadata satisfy it.
type resourceRef interface {
	GetAtespace() string
	GetName() string
}

func onActor(relation string, ref resourceRef) []check {
	if ref.GetAtespace() == "" || ref.GetName() == "" {
		return nil
	}
	return []check{{relation: relation, object: ActorObject(ref.GetAtespace(), ref.GetName())}}
}

func onActorTemplate(relation string, ref resourceRef) []check {
	if ref.GetAtespace() == "" || ref.GetName() == "" {
		return nil
	}
	return []check{{relation: relation, object: ActorTemplateObject(ref.GetAtespace(), ref.GetName())}}
}

// rpcRule is the permission rule for one RPC.
type rpcRule struct {
	extract checkExtractor
	// alwaysEnforce marks RPCs that are checked even when enforcement is
	// disabled. AccessPolicy RPCs set it so that nobody can grant themselves
	// access while enforcement is off and keep that grant once it is turned on.
	alwaysEnforce bool
}

func rule(extract checkExtractor) rpcRule {
	return rpcRule{extract: extract}
}

func governance(extract checkExtractor) rpcRule {
	return rpcRule{extract: extract, alwaysEnforce: true}
}

// defaultRPCPermissions is the declarative registry mapping gRPC full method names
// to their permission rules.
var defaultRPCPermissions = map[string]rpcRule{
	// Atespaces.
	ateapipb.Control_CreateAtespace_FullMethodName: rule(checksOf(func(*ateapipb.CreateAtespaceRequest) []check {
		return onGlobal(RelationCanCreateAtespace)
	})),
	ateapipb.Control_ListAtespaces_FullMethodName: rule(checksOf(func(*ateapipb.ListAtespacesRequest) []check {
		return onGlobal(RelationCanListAtespaces)
	})),
	ateapipb.Control_GetAtespace_FullMethodName: rule(checksOf(func(r *ateapipb.GetAtespaceRequest) []check {
		return onAtespace(RelationCanGet, r.GetAtespace().GetName())
	})),
	ateapipb.Control_DeleteAtespace_FullMethodName: rule(checksOf(func(r *ateapipb.DeleteAtespaceRequest) []check {
		return onAtespace(RelationCanDelete, r.GetAtespace().GetName())
	})),

	// Access policies.
	ateapipb.Control_GetGlobalAccessPolicy_FullMethodName: governance(checksOf(func(*ateapipb.GetGlobalAccessPolicyRequest) []check {
		return onGlobal(RelationCanGetAccessPolicy)
	})),
	ateapipb.Control_CreateGlobalAccessPolicy_FullMethodName: governance(checksOf(func(*ateapipb.CreateGlobalAccessPolicyRequest) []check {
		return onGlobal(RelationCanCreateAccessPolicy)
	})),
	ateapipb.Control_UpdateGlobalAccessPolicy_FullMethodName: governance(checksOf(func(*ateapipb.UpdateGlobalAccessPolicyRequest) []check {
		return onGlobal(RelationCanUpdateAccessPolicy)
	})),
	ateapipb.Control_GetAtespaceAccessPolicy_FullMethodName: governance(checksOf(func(r *ateapipb.GetAtespaceAccessPolicyRequest) []check {
		return onAtespace(RelationCanGetAccessPolicy, r.GetAtespace().GetName())
	})),
	ateapipb.Control_CreateAtespaceAccessPolicy_FullMethodName: governance(checksOf(func(r *ateapipb.CreateAtespaceAccessPolicyRequest) []check {
		return onAtespace(RelationCanCreateAccessPolicy, r.GetAtespace().GetName())
	})),
	ateapipb.Control_UpdateAtespaceAccessPolicy_FullMethodName: governance(checksOf(func(r *ateapipb.UpdateAtespaceAccessPolicyRequest) []check {
		return onAtespace(RelationCanUpdateAccessPolicy, r.GetAtespace().GetName())
	})),
	ateapipb.Control_DeleteAtespaceAccessPolicy_FullMethodName: governance(checksOf(func(r *ateapipb.DeleteAtespaceAccessPolicyRequest) []check {
		return onAtespace(RelationCanDeleteAccessPolicy, r.GetAtespace().GetName())
	})),

	// Actor templates.
	ateapipb.Control_CreateActorTemplate_FullMethodName: rule(checksOf(func(r *ateapipb.CreateActorTemplateRequest) []check {
		return onAtespace(RelationCanCreateActorTemplate, r.GetActorTemplate().GetMetadata().GetAtespace())
	})),
	ateapipb.Control_GetActorTemplate_FullMethodName: rule(checksOf(func(r *ateapipb.GetActorTemplateRequest) []check {
		return onActorTemplate(RelationCanGet, r.GetActorTemplate())
	})),
	ateapipb.Control_ListActorTemplates_FullMethodName: rule(checksOf(func(r *ateapipb.ListActorTemplatesRequest) []check {
		return onAtespaceOrGlobal(RelationCanListActorTemplates, r.GetAtespace())
	})),
	ateapipb.Control_DeleteActorTemplate_FullMethodName: rule(checksOf(func(r *ateapipb.DeleteActorTemplateRequest) []check {
		return onActorTemplate(RelationCanDelete, r.GetActorTemplate())
	})),

	// Actors. Creating or updating an actor also requires can_use on the actor
	// template it runs, which may live in another atespace.
	ateapipb.Control_CreateActor_FullMethodName: rule(checksOf(func(r *ateapipb.CreateActorRequest) []check {
		return slices.Concat(
			onAtespace(RelationCanCreateActor, r.GetActor().GetMetadata().GetAtespace()),
			onActorTemplate(RelationCanUse, r.GetActor().GetActorTemplate()),
		)
	})),
	ateapipb.Control_GetActor_FullMethodName: rule(checksOf(func(r *ateapipb.GetActorRequest) []check {
		return onActor(RelationCanGet, r.GetActor())
	})),
	ateapipb.Control_ListActors_FullMethodName: rule(checksOf(func(r *ateapipb.ListActorsRequest) []check {
		return onAtespaceOrGlobal(RelationCanListActors, r.GetAtespace())
	})),
	ateapipb.Control_UpdateActor_FullMethodName: rule(checksOf(func(r *ateapipb.UpdateActorRequest) []check {
		return slices.Concat(
			onActor(RelationCanUpdate, r.GetActor().GetMetadata()),
			onActorTemplate(RelationCanUse, r.GetActor().GetActorTemplate()),
		)
	})),
	ateapipb.Control_DeleteActor_FullMethodName: rule(checksOf(func(r *ateapipb.DeleteActorRequest) []check {
		return onActor(RelationCanDelete, r.GetActor())
	})),
}
