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
	"errors"
	"fmt"
	"testing"

	"github.com/agent-substrate/substrate/cmd/ateapi/internal/authz"
	"github.com/agent-substrate/substrate/cmd/ateapi/internal/store"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func TestMapAccessPolicyWrite_Codes(t *testing.T) {
	// OpenFGA reports tuple validation failures with nonstandard codes such as 2000.
	openFGAErr := status.Error(codes.Code(2000), "invalid tuple")

	tests := []struct {
		name string
		err  error
		want codes.Code
	}{
		{name: "authz disabled", err: store.ErrAuthzDisabled, want: codes.FailedPrecondition},
		{name: "wrapped authz disabled", err: fmt.Errorf("op: %w", store.ErrAuthzDisabled), want: codes.FailedPrecondition},
		{name: "nonstandard backend code", err: openFGAErr, want: codes.Internal},
		{name: "wrapped nonstandard backend code", err: fmt.Errorf("reconciling: %w", openFGAErr), want: codes.Internal},
		{name: "canonical status passes through", err: status.Error(codes.InvalidArgument, "bad"), want: codes.InvalidArgument},
		{name: "plain error", err: errors.New("boom"), want: codes.Unknown},
		{name: "not found", err: store.ErrNotFound, want: codes.NotFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := mapAccessPolicyWrite(nil, tc.err)
			if got := status.Code(err); got != tc.want {
				t.Errorf("mapAccessPolicyWrite(%v) code = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestValidateAccessPolicyBindings_RejectsControlCharacters(t *testing.T) {
	policy := &ateapipb.AccessPolicy{
		Bindings: []*ateapipb.Binding{{Role: authz.RoleOwner, Members: []string{"user:alice\tbob"}}},
	}
	errs := validateAccessPolicyBindings(field.NewPath("bindings"), policy, validAtespaceRoles)
	if len(errs) != 1 || errs[0].Type != field.ErrorTypeInvalid || errs[0].Field != "bindings[0].members[0]" {
		t.Fatalf("validateAccessPolicyBindings = %v, want one Invalid error on bindings[0].members[0]", errs)
	}
}
