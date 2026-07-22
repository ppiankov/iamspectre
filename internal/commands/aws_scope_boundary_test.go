package commands

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

// WO-22@v3: enumerate the exact actions emitted by the initialization template.
// WO-113@v3: include the read-only role enrichment prerequisite.
var expectedInitAWSActions = []string{
	"iam:GenerateCredentialReport", "iam:GetCredentialReport", "iam:GetPolicy",
	"iam:GetPolicyVersion", "iam:GetRole", "iam:ListAttachedRolePolicies", "iam:ListAttachedUserPolicies",
	"iam:ListPolicies", "iam:ListRoles", "iam:ListUsers", "sts:GetCallerIdentity",
}

// WO-23@v2: distinguish verified runtime calls from permissions awaiting an operator decision.
type awsActionEvidence struct {
	productionSite string
	decision       string
}

// WO-23@v2: bind every generated AWS permission to runtime evidence or an explicit review decision.
var awsPolicyActionEvidence = map[string]awsActionEvidence{
	"iam:GenerateCredentialReport": {productionSite: "internal/aws/credential_report.go:48 FetchCredentialReport", decision: "direct"},
	"iam:GetCredentialReport":      {productionSite: "internal/aws/credential_report.go:64 FetchCredentialReport", decision: "direct"},
	"iam:GetPolicy":                {decision: "unjustified"},
	"iam:GetPolicyVersion":         {productionSite: "internal/aws/policy.go:75 PolicyScanner.checkWildcardPolicy", decision: "direct"},
	"iam:GetRole":                  {productionSite: "internal/aws/role.go RoleScanner.resolveRoleLastUsed", decision: "direct"}, // WO-113@v3: generated credentials must cover runtime role enrichment.
	"iam:ListAttachedRolePolicies": {decision: "unjustified"},
	"iam:ListAttachedUserPolicies": {decision: "unjustified"},
	"iam:ListPolicies":             {productionSite: "internal/aws/policy.go:126 PolicyScanner.listPolicies", decision: "direct"},
	"iam:ListRoles":                {productionSite: "internal/aws/role.go:179 RoleScanner.listRoles", decision: "direct"},
	"iam:ListUsers":                {decision: "unjustified"},
	"sts:GetCallerIdentity":        {productionSite: "internal/aws/client.go:63 Client.GetAccountID", decision: "direct"},
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

// WO-23@v2: fail closed when the generated policy and its runtime evidence drift apart.
func TestInitAWSActionEvidence(t *testing.T) {
	expectedDirectSites := map[string]string{
		"iam:GenerateCredentialReport": "internal/aws/credential_report.go:48 FetchCredentialReport",
		"iam:GetCredentialReport":      "internal/aws/credential_report.go:64 FetchCredentialReport",
		"iam:GetPolicyVersion":         "internal/aws/policy.go:75 PolicyScanner.checkWildcardPolicy",
		"iam:GetRole":                  "internal/aws/role.go RoleScanner.resolveRoleLastUsed",
		"iam:ListPolicies":             "internal/aws/policy.go:126 PolicyScanner.listPolicies",
		"iam:ListRoles":                "internal/aws/role.go:179 RoleScanner.listRoles",
		"sts:GetCallerIdentity":        "internal/aws/client.go:63 Client.GetAccountID",
	}
	expectedUnjustified := map[string]bool{
		"iam:GetPolicy": true, "iam:ListAttachedRolePolicies": true,
		"iam:ListAttachedUserPolicies": true, "iam:ListUsers": true,
	}
	var policy struct {
		Statement []struct {
			Action []string
		}
	}
	if err := json.Unmarshal([]byte(sampleAWSIAMPolicy), &policy); err != nil {
		t.Fatalf("parse sample policy: %v", err)
	}
	if len(policy.Statement) != 1 {
		t.Fatalf("statements = %d, want 1", len(policy.Statement))
	}

	generated := make(map[string]struct{}, len(policy.Statement[0].Action))
	for _, action := range policy.Statement[0].Action {
		if _, exists := generated[action]; exists {
			t.Fatalf("duplicate generated action %q", action)
		}
		generated[action] = struct{}{}
		evidence, ok := awsPolicyActionEvidence[action]
		if !ok {
			t.Errorf("generated action %q lacks runtime evidence", action)
			continue
		}
		if evidence.decision != "direct" && evidence.decision != "unjustified" {
			t.Errorf("action %q has invalid decision %q", action, evidence.decision)
		}
		if evidence.decision == "direct" {
			want, expected := expectedDirectSites[action]
			if !expected || evidence.productionSite != want {
				t.Errorf("direct evidence for %q = %+v, want site %q", action, evidence, want)
			}
		}
		if evidence.decision == "unjustified" && (!expectedUnjustified[action] || evidence.productionSite != "") {
			t.Errorf("unjustified evidence for %q = %+v", action, evidence)
		}
	}
	for action := range awsPolicyActionEvidence {
		if _, ok := generated[action]; !ok {
			t.Errorf("stale evidence for action %q", action)
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
