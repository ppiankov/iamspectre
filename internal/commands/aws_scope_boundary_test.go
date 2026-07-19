package commands

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

// WO-22@v3: enumerate the exact actions emitted by the initialization template.
var expectedInitAWSActions = []string{
	"iam:GenerateCredentialReport", "iam:GetCredentialReport", "iam:GetPolicy",
	"iam:GetPolicyVersion", "iam:ListAttachedRolePolicies", "iam:ListAttachedUserPolicies",
	"iam:ListPolicies", "iam:ListRoles", "iam:ListUsers", "sts:GetCallerIdentity",
}

// WO-22@v3: keep generated credentials bounded to the reviewed read-only action set.
func TestInitAWSPermissionBoundary(t *testing.T) {
	var policy struct {
		Statement []struct {
			Effect string
			Action []string
		}
	}
	if err := json.Unmarshal([]byte(sampleAWSIAMPolicy), &policy); err != nil {
		t.Fatalf("parse sample policy: %v", err)
	}
	if len(policy.Statement) != 1 || policy.Statement[0].Effect != "Allow" {
		t.Fatalf("expected one Allow statement")
	}
	actions := append([]string(nil), policy.Statement[0].Action...)
	sort.Strings(actions)
	want := append([]string(nil), expectedInitAWSActions...)
	sort.Strings(want)
	if len(actions) != len(want) {
		t.Fatalf("actions = %v, want %v", actions, want)
	}
	for i := range want {
		if actions[i] != want[i] {
			t.Fatalf("actions = %v, want %v", actions, want)
		}
		if !isAllowedInitAction(actions[i]) {
			t.Fatalf("action is outside boundary: %s", actions[i])
		}
	}
}

// WO-22@v3: mutation proof rejects foreign and wildcard actions.
func TestInitAWSPermissionBoundaryRejectsForeignAction(t *testing.T) {
	if isAllowedInitAction("s3:GetObject") {
		t.Fatal("s3:GetObject must be rejected")
	}
	if isAllowedInitAction("iam:*") {
		t.Fatal("wildcards must be rejected")
	}
}

// WO-22@v3: reject wildcards and actions not present in the reviewed set.
func isAllowedInitAction(action string) bool {
	if strings.ContainsAny(action, "*?") {
		return false
	}
	for _, allowed := range expectedInitAWSActions {
		if action == allowed {
			return true
		}
	}
	return false
}
