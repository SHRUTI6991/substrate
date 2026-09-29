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
	"testing"

	"github.com/agent-substrate/substrate/internal/apierror"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/grpc/codes"
)

func TestDefaultRPCPermissions(t *testing.T) {
	actorRef := &ateapipb.ObjectRef{Atespace: "team-a", Name: "runner"}
	actorMeta := &ateapipb.ResourceMetadata{Atespace: "team-a", Name: "runner"}
	localTemplate := &ateapipb.ObjectRef{Atespace: "team-a", Name: "tmpl"}
	sharedTemplate := &ateapipb.ObjectRef{Atespace: "shared", Name: "tmpl"}

	tests := []struct {
		name       string
		fullMethod string
		req        any
		want       []check
	}{
		// Atespaces.
		{
			name:       "CreateAtespace",
			fullMethod: ateapipb.Control_CreateAtespace_FullMethodName,
			req:        &ateapipb.CreateAtespaceRequest{},
			want:       []check{{RelationCanCreateAtespace, GlobalRootObject}},
		},
		{
			name:       "ListAtespaces",
			fullMethod: ateapipb.Control_ListAtespaces_FullMethodName,
			req:        &ateapipb.ListAtespacesRequest{},
			want:       []check{{RelationCanListAtespaces, GlobalRootObject}},
		},
		{
			name:       "GetAtespace",
			fullMethod: ateapipb.Control_GetAtespace_FullMethodName,
			req:        &ateapipb.GetAtespaceRequest{Atespace: &ateapipb.ObjectRef{Name: "team-a"}},
			want:       []check{{RelationCanGet, "atespace:team-a"}},
		},
		{
			name:       "DeleteAtespace",
			fullMethod: ateapipb.Control_DeleteAtespace_FullMethodName,
			req:        &ateapipb.DeleteAtespaceRequest{Atespace: &ateapipb.ObjectRef{Name: "team-a"}},
			want:       []check{{RelationCanDelete, "atespace:team-a"}},
		},

		// Actor templates.
		{
			name:       "CreateActorTemplate",
			fullMethod: ateapipb.Control_CreateActorTemplate_FullMethodName,
			req: &ateapipb.CreateActorTemplateRequest{ActorTemplate: &ateapipb.ActorTemplate{
				Metadata: &ateapipb.ResourceMetadata{Atespace: "team-a", Name: "tmpl"},
			}},
			want: []check{{RelationCanCreateActorTemplate, "atespace:team-a"}},
		},
		{
			name:       "GetActorTemplate",
			fullMethod: ateapipb.Control_GetActorTemplate_FullMethodName,
			req:        &ateapipb.GetActorTemplateRequest{ActorTemplate: localTemplate},
			want:       []check{{RelationCanGet, "actor_template:team-a/tmpl"}},
		},
		{
			name:       "ListActorTemplates in an atespace",
			fullMethod: ateapipb.Control_ListActorTemplates_FullMethodName,
			req:        &ateapipb.ListActorTemplatesRequest{Atespace: "team-a"},
			want:       []check{{RelationCanListActorTemplates, "atespace:team-a"}},
		},
		{
			name:       "ListActorTemplates across all atespaces",
			fullMethod: ateapipb.Control_ListActorTemplates_FullMethodName,
			req:        &ateapipb.ListActorTemplatesRequest{},
			want:       []check{{RelationCanListActorTemplates, GlobalRootObject}},
		},
		{
			name:       "DeleteActorTemplate",
			fullMethod: ateapipb.Control_DeleteActorTemplate_FullMethodName,
			req:        &ateapipb.DeleteActorTemplateRequest{ActorTemplate: localTemplate},
			want:       []check{{RelationCanDelete, "actor_template:team-a/tmpl"}},
		},

		// Actors.
		{
			name:       "CreateActor checks the atespace and the template",
			fullMethod: ateapipb.Control_CreateActor_FullMethodName,
			req:        &ateapipb.CreateActorRequest{Actor: &ateapipb.Actor{Metadata: actorMeta, ActorTemplate: sharedTemplate}},
			want: []check{
				{RelationCanCreateActor, "atespace:team-a"},
				{RelationCanUse, "actor_template:shared/tmpl"},
			},
		},
		{
			name:       "GetActor",
			fullMethod: ateapipb.Control_GetActor_FullMethodName,
			req:        &ateapipb.GetActorRequest{Actor: actorRef},
			want:       []check{{RelationCanGet, "actor:team-a/runner"}},
		},
		{
			name:       "ListActors in an atespace",
			fullMethod: ateapipb.Control_ListActors_FullMethodName,
			req:        &ateapipb.ListActorsRequest{Atespace: "team-a"},
			want:       []check{{RelationCanListActors, "atespace:team-a"}},
		},
		{
			name:       "ListActors across all atespaces",
			fullMethod: ateapipb.Control_ListActors_FullMethodName,
			req:        &ateapipb.ListActorsRequest{},
			want:       []check{{RelationCanListActors, GlobalRootObject}},
		},
		{
			name:       "UpdateActor checks the actor and the template",
			fullMethod: ateapipb.Control_UpdateActor_FullMethodName,
			req:        &ateapipb.UpdateActorRequest{Actor: &ateapipb.Actor{Metadata: actorMeta, ActorTemplate: sharedTemplate}},
			want: []check{
				{RelationCanUpdate, "actor:team-a/runner"},
				{RelationCanUse, "actor_template:shared/tmpl"},
			},
		},
		{
			name:       "DeleteActor",
			fullMethod: ateapipb.Control_DeleteActor_FullMethodName,
			req:        &ateapipb.DeleteActorRequest{Actor: actorRef},
			want:       []check{{RelationCanDelete, "actor:team-a/runner"}},
		},

		// Checks on identifiers missing from malformed requests are left out, and
		// the rest still apply. The handler rejects the missing fields.
		{
			name:       "GetActor without a name",
			fullMethod: ateapipb.Control_GetActor_FullMethodName,
			req:        &ateapipb.GetActorRequest{Actor: &ateapipb.ObjectRef{Atespace: "team-a"}},
			want:       nil,
		},
		{
			name:       "CreateActor without an actor",
			fullMethod: ateapipb.Control_CreateActor_FullMethodName,
			req:        &ateapipb.CreateActorRequest{},
			want:       nil,
		},
		{
			name:       "CreateActor without a template still checks the atespace",
			fullMethod: ateapipb.Control_CreateActor_FullMethodName,
			req:        &ateapipb.CreateActorRequest{Actor: &ateapipb.Actor{Metadata: actorMeta}},
			want:       []check{{RelationCanCreateActor, "atespace:team-a"}},
		},
		{
			name:       "CreateActor with a template missing its atespace still checks the atespace",
			fullMethod: ateapipb.Control_CreateActor_FullMethodName,
			req: &ateapipb.CreateActorRequest{Actor: &ateapipb.Actor{
				Metadata:      actorMeta,
				ActorTemplate: &ateapipb.ObjectRef{Name: "tmpl"},
			}},
			want: []check{{RelationCanCreateActor, "atespace:team-a"}},
		},
		{
			name:       "UpdateActor without metadata still checks the template",
			fullMethod: ateapipb.Control_UpdateActor_FullMethodName,
			req:        &ateapipb.UpdateActorRequest{Actor: &ateapipb.Actor{ActorTemplate: sharedTemplate}},
			want:       []check{{RelationCanUse, "actor_template:shared/tmpl"}},
		},
		{
			name:       "UpdateActor without a template still checks the actor",
			fullMethod: ateapipb.Control_UpdateActor_FullMethodName,
			req:        &ateapipb.UpdateActorRequest{Actor: &ateapipb.Actor{Metadata: actorMeta}},
			want:       []check{{RelationCanUpdate, "actor:team-a/runner"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, ok := defaultRPCPermissions[tc.fullMethod]
			if !ok {
				t.Fatalf("%s is not registered", tc.fullMethod)
			}
			got, err := r.extract(tc.req)
			if err != nil {
				t.Fatalf("extract() error = %v", err)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("extract() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDefaultRPCPermissions_UnexpectedRequestTypeFailsClosed(t *testing.T) {
	for fullMethod, r := range defaultRPCPermissions {
		if _, err := r.extract("wrong-type"); apierror.Code(err) != codes.Internal {
			t.Errorf("%s: extract(wrong type) error = %v, want code Internal", fullMethod, err)
		}
	}
}
