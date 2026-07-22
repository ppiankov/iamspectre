package aws

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	iamsvc "github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/ppiankov/iamspectre/internal/iam"
)

func TestRoleScanner_UnusedRole(t *testing.T) {
	staleDate := time.Now().UTC().AddDate(0, 0, -120)
	mock := &mockIAM{
		roles: []iamtypes.Role{
			{
				RoleName:   awssdk.String("old-role"),
				Arn:        awssdk.String("arn:aws:iam::123456789012:role/old-role"),
				Path:       awssdk.String("/"),
				CreateDate: awssdk.Time(time.Now().UTC().AddDate(-1, 0, 0)),
				RoleLastUsed: &iamtypes.RoleLastUsed{
					LastUsedDate: &staleDate,
				},
			},
		},
	}

	scanner := NewRoleScanner(mock, "123456789012")
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if result.PrincipalsScanned != 1 {
		t.Fatalf("expected 1 principal scanned, got %d", result.PrincipalsScanned)
	}

	found := findFinding(result.Findings, iam.FindingUnusedRole)
	if found == nil {
		t.Fatal("expected UNUSED_ROLE finding")
	}
	if found.Severity != iam.SeverityMedium {
		t.Fatalf("expected medium severity, got %s", found.Severity)
	}
}

// WO-54@v3: creation age cannot substitute for unavailable RoleLastUsed evidence.
// WO-104@v3: missing usage evidence belongs to the coverage plane, not per-role errors.
func TestRoleScanner_NeverUsedRole(t *testing.T) {
	oldCreateDate := time.Now().UTC().AddDate(-1, 0, 0)
	mock := &mockIAM{
		roles: []iamtypes.Role{
			{
				RoleName:     awssdk.String("never-used"),
				Arn:          awssdk.String("arn:aws:iam::123456789012:role/never-used"),
				Path:         awssdk.String("/"),
				CreateDate:   &oldCreateDate,
				RoleLastUsed: nil,
			},
		},
	}

	scanner := NewRoleScanner(mock, "123456789012")
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if findFinding(result.Findings, iam.FindingUnusedRole) != nil {
		t.Fatal("missing RoleLastUsed evidence must not emit UNUSED_ROLE")
	}
	assertRoleUsageCoverage(t, result, 1, 0, 1)
}

// WO-104@v3: validate the canonical role-usage observation without coupling to reporter aggregation.
func assertRoleUsageCoverage(t *testing.T, result *iam.ScanResult, affected, evaluable, total int) {
	assertRoleUsageCoverageCause(t, result, "evidence_unavailable", affected, evaluable, total)
}

// WO-110@v5: assert the legacy aggregate without coupling to role-level private detail.
func assertRoleUsageCoverageCause(t *testing.T, result *iam.ScanResult, cause string, affected, evaluable, total int) {
	t.Helper()
	if len(result.Errors) != 0 {
		t.Fatalf("errors = %#v, want no missing-evidence diagnostics", result.Errors)
	}
	if len(result.CoverageGaps) != 1 {
		t.Fatalf("coverage gaps = %#v, want one role-usage observation", result.CoverageGaps)
	}
	gap := result.CoverageGaps[0]
	if gap.Capability != "aws_role_last_used" || gap.Cause != cause ||
		gap.Scope != "aws-account:123456789012" || gap.FindingID != iam.FindingUnusedRole ||
		gap.AffectedCount != affected || gap.EvaluableCount != evaluable || gap.TotalCount != total ||
		gap.MaxConsequence != iam.SeverityMedium {
		t.Fatalf("coverage gap = %#v, want affected=%d evaluable=%d total=%d", gap, affected, evaluable, total)
	}
}

func TestRoleScanner_RecentlyUsedRole(t *testing.T) {
	recentDate := time.Now().UTC().AddDate(0, 0, -5)
	mock := &mockIAM{
		roles: []iamtypes.Role{
			{
				RoleName:   awssdk.String("active-role"),
				Arn:        awssdk.String("arn:aws:iam::123456789012:role/active-role"),
				Path:       awssdk.String("/"),
				CreateDate: awssdk.Time(time.Now().UTC().AddDate(-1, 0, 0)),
				RoleLastUsed: &iamtypes.RoleLastUsed{
					LastUsedDate: &recentDate,
				},
			},
		},
	}

	scanner := NewRoleScanner(mock, "123456789012")
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for active role, got %d", len(result.Findings))
	}
}

// WO-44@v2: default scanning suppresses only unused-role noise for every canonical shape.
func TestRoleScanner_ServiceLinkedRoleSkipped(t *testing.T) {
	mock := &mockIAM{
		roles: []iamtypes.Role{
			{
				RoleName:     awssdk.String("AWSServiceRoleForECS"),
				Arn:          awssdk.String("arn:aws:iam::123456789012:role/aws-service-role/ecs.amazonaws.com/AWSServiceRoleForECS"),
				Path:         awssdk.String("/aws-service-role/ecs.amazonaws.com/"),
				CreateDate:   awssdk.Time(time.Now().UTC().AddDate(-2, 0, 0)),
				RoleLastUsed: nil,
			},
			{
				RoleName: awssdk.String("custom-name"),
				Arn:      awssdk.String("arn:aws:iam::123456789012:role/aws-service-role/example.amazonaws.com/custom-name"),
				Path:     awssdk.String("/"), CreateDate: awssdk.Time(time.Now().UTC().AddDate(-2, 0, 0)),
			},
			{
				RoleName: awssdk.String("AWSServiceRoleForNameOnly"),
				Arn:      awssdk.String("arn:aws:iam::123456789012:role/AWSServiceRoleForNameOnly"),
				Path:     awssdk.String("/"), CreateDate: awssdk.Time(time.Now().UTC().AddDate(-2, 0, 0)),
			},
		},
	}

	scanner := NewRoleScanner(mock, "123456789012")
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for service-linked role, got %d", len(result.Findings))
	}
}

// WO-44@v2: opted-in stale service-linked roles use restrained guidance.
// WO-51: stale Identity Center roles retain family-specific low-risk guidance.
func TestRoleScanner_AWSOwnedStaleRoleGuidance(t *testing.T) {
	stale := time.Now().UTC().AddDate(0, 0, -120)
	tests := []struct {
		name     string
		role     iamtypes.Role
		cfg      iam.ScanConfig
		guidance string
	}{
		{
			name: "service linked",
			role: iamtypes.Role{
				RoleName:     awssdk.String("AWSServiceRoleForExample"),
				Arn:          awssdk.String("arn:aws:iam::123456789012:role/aws-service-role/example.amazonaws.com/AWSServiceRoleForExample"),
				Path:         awssdk.String("/aws-service-role/example.amazonaws.com/"),
				CreateDate:   awssdk.Time(time.Now().UTC().AddDate(-2, 0, 0)),
				RoleLastUsed: &iamtypes.RoleLastUsed{LastUsedDate: &stale},
			},
			cfg:      iam.ScanConfig{StaleDays: 90, IncludeServiceLinkedRoles: true},
			guidance: "owning AWS service",
		},
		{
			name: "identity center",
			role: iamtypes.Role{
				RoleName:     awssdk.String("AWSReservedSSO_ReadOnly_0123456789abcdef"),
				Arn:          awssdk.String("arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_ReadOnly_0123456789abcdef"),
				Path:         awssdk.String("/aws-reserved/sso.amazonaws.com/"),
				CreateDate:   awssdk.Time(time.Now().UTC().AddDate(-2, 0, 0)),
				RoleLastUsed: &iamtypes.RoleLastUsed{LastUsedDate: &stale},
			},
			cfg:      iam.ScanConfig{StaleDays: 90},
			guidance: "IAM Identity Center",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := NewRoleScanner(&mockIAM{roles: []iamtypes.Role{tt.role}}, "123456789012").Scan(context.Background(), tt.cfg)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			finding := findFinding(result.Findings, iam.FindingUnusedRole)
			if finding == nil || finding.Severity != iam.SeverityLow || !strings.Contains(finding.Recommendation, tt.guidance) {
				t.Fatalf("finding = %#v, want low severity and %q guidance", finding, tt.guidance)
			}
		})
	}
}

// WO-44@v2: service-linked classification uses only structural AWS identifiers.
func TestIsServiceLinkedRole(t *testing.T) {
	tests := []struct {
		name string
		role iamtypes.Role
		want bool
	}{
		{name: "path", role: iamtypes.Role{Path: awssdk.String("/aws-service-role/ecs.amazonaws.com/")}, want: true},
		{name: "arn", role: iamtypes.Role{Arn: awssdk.String("arn:aws:iam::123456789012:role/aws-service-role/ecs.amazonaws.com/example")}, want: true},
		{name: "name", role: iamtypes.Role{RoleName: awssdk.String("AWSServiceRoleForECS")}, want: true},
		{name: "customer", role: iamtypes.Role{Path: awssdk.String("/"), RoleName: awssdk.String("AWS-Custom")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isServiceLinkedRole(tt.role); got != tt.want {
				t.Fatalf("isServiceLinkedRole() = %v, want %v", got, tt.want)
			}
		})
	}
}

// WO-51: both reserved path and canonical name are required for Identity Center classification.
func TestIsIdentityCenterRole(t *testing.T) {
	canonical := iamtypes.Role{
		Path:     awssdk.String("/aws-reserved/sso.amazonaws.com/"),
		RoleName: awssdk.String("AWSReservedSSO_ReadOnly_0123456789abcdef"),
	}
	if !isIdentityCenterRole(canonical) {
		t.Fatal("expected canonical Identity Center role")
	}
	canonical.Path = awssdk.String("/")
	if isIdentityCenterRole(canonical) {
		t.Fatal("name alone must not classify a customer role")
	}
	canonical.Path = awssdk.String("/aws-reserved/sso.amazonaws.com/")
	canonical.RoleName = awssdk.String("custom")
	if isIdentityCenterRole(canonical) {
		t.Fatal("path alone must not classify a customer role")
	}
}

// WO-44@v2: opt-in service-linked findings use restrained severity and guidance.
// WO-104@v3: opted-in roles contribute to the usage-evidence denominator.
func TestRoleScanner_ServiceLinkedRoleIncluded(t *testing.T) {
	created := time.Now().UTC().AddDate(-2, 0, 0)
	mock := &mockIAM{roles: []iamtypes.Role{{
		RoleName: awssdk.String("AWSServiceRoleForExample"),
		Arn:      awssdk.String("arn:aws:iam::123456789012:role/aws-service-role/example.amazonaws.com/AWSServiceRoleForExample"),
		Path:     awssdk.String("/aws-service-role/example.amazonaws.com/"), CreateDate: &created,
	}}}
	result, err := NewRoleScanner(mock, "123456789012").Scan(
		context.Background(),
		iam.ScanConfig{StaleDays: 90, IncludeServiceLinkedRoles: true},
	)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if findFinding(result.Findings, iam.FindingUnusedRole) != nil {
		t.Fatal("missing RoleLastUsed evidence must not emit UNUSED_ROLE")
	}
	assertRoleUsageCoverage(t, result, 1, 0, 1)
}

// WO-44@v2: UNUSED_ROLE suppression must not bypass independent trust analysis.
func TestRoleScanner_ServiceLinkedRoleStillChecksTrust(t *testing.T) {
	trust := url.QueryEscape(`{"Statement":{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}}`)
	mock := &mockIAM{roles: []iamtypes.Role{{
		RoleName:                 awssdk.String("AWSServiceRoleForExample"),
		Arn:                      awssdk.String("arn:aws:iam::123456789012:role/aws-service-role/example.amazonaws.com/AWSServiceRoleForExample"),
		Path:                     awssdk.String("/aws-service-role/example.amazonaws.com/"),
		CreateDate:               awssdk.Time(time.Now().UTC().AddDate(-2, 0, 0)),
		AssumeRolePolicyDocument: awssdk.String(trust),
	}}}
	result, err := NewRoleScanner(mock, "123456789012").Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if findFinding(result.Findings, iam.FindingUnusedRole) != nil {
		t.Fatal("expected UNUSED_ROLE suppression")
	}
	if findFinding(result.Findings, iam.FindingCrossAccountTrust) == nil {
		t.Fatal("expected CROSS_ACCOUNT_TRUST finding")
	}
}

// WO-50: missing creation evidence cannot justify a fabricated unused-role age.
// WO-54@v3: missing RoleLastUsed evidence is independent of creation evidence.
// WO-104@v3: mixed evidence records one unavailable and one evaluable opportunity.
func TestRoleScanner_MissingCreateDate(t *testing.T) {
	trust := url.QueryEscape(`{"Statement":{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}}`)
	stale := time.Now().UTC().AddDate(0, 0, -120)
	mock := &mockIAM{roles: []iamtypes.Role{
		{
			RoleName:                 awssdk.String("unknown-age"),
			Arn:                      awssdk.String("arn:aws:iam::123456789012:role/unknown-age"),
			Path:                     awssdk.String("/"),
			AssumeRolePolicyDocument: awssdk.String(trust),
		},
		{
			RoleName:     awssdk.String("later-stale-role"),
			Arn:          awssdk.String("arn:aws:iam::123456789012:role/later-stale-role"),
			Path:         awssdk.String("/"),
			CreateDate:   awssdk.Time(time.Now().UTC().AddDate(-2, 0, 0)),
			RoleLastUsed: &iamtypes.RoleLastUsed{LastUsedDate: &stale},
		},
	}}
	result, err := NewRoleScanner(mock, "123456789012").Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, finding := range result.Findings {
		if finding.ID == iam.FindingUnusedRole && finding.ResourceName == "unknown-age" {
			t.Fatal("missing CreateDate must not emit UNUSED_ROLE")
		}
	}
	assertRoleUsageCoverage(t, result, 1, 1, 2)
	if findFinding(result.Findings, iam.FindingCrossAccountTrust) == nil {
		t.Fatal("missing CreateDate must not bypass trust evaluation")
	}
	if finding := findFinding(result.Findings, iam.FindingUnusedRole); finding == nil || finding.ResourceName != "later-stale-role" {
		t.Fatalf("subsequent role was not evaluated: %#v", result.Findings)
	}
}

// WO-51: Identity Center roles require assignment-oriented remediation.
// WO-104@v3: Identity Center roles use the same missing-evidence coverage boundary.
func TestRoleScanner_IdentityCenterReservedRole(t *testing.T) {
	created := time.Now().UTC().AddDate(-2, 0, 0)
	mock := &mockIAM{roles: []iamtypes.Role{{
		RoleName: awssdk.String("AWSReservedSSO_ReadOnly_0123456789abcdef"),
		Arn:      awssdk.String("arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_ReadOnly_0123456789abcdef"),
		Path:     awssdk.String("/aws-reserved/sso.amazonaws.com/"), CreateDate: &created,
	}}}
	result, err := NewRoleScanner(mock, "123456789012").Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if findFinding(result.Findings, iam.FindingUnusedRole) != nil {
		t.Fatal("missing RoleLastUsed evidence must not emit UNUSED_ROLE")
	}
	assertRoleUsageCoverage(t, result, 1, 0, 1)
}

// WO-46: malformed trust documents must be present in reportable scan errors.
func TestRoleScanner_TrustPolicyParseError(t *testing.T) {
	stale := time.Now().UTC().AddDate(0, 0, -120)
	mock := &mockIAM{roles: []iamtypes.Role{{
		RoleName:                 awssdk.String("bad-trust"),
		Arn:                      awssdk.String("arn:aws:iam::123456789012:role/bad-trust"),
		Path:                     awssdk.String("/"),
		CreateDate:               awssdk.Time(time.Now().UTC().AddDate(-2, 0, 0)),
		RoleLastUsed:             &iamtypes.RoleLastUsed{LastUsedDate: &stale},
		AssumeRolePolicyDocument: awssdk.String(url.QueryEscape(`{"Statement":42}`)),
	}}}
	result, err := NewRoleScanner(mock, "123456789012").Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(result.Errors) != 1 || !strings.Contains(result.Errors[0], "bad-trust") {
		t.Fatalf("errors = %#v, want one role-qualified parse error", result.Errors)
	}
	if findFinding(result.Findings, iam.FindingUnusedRole) == nil {
		t.Fatal("malformed trust must not suppress a known stale finding")
	}
}

// WO-54@v3: recognize only determinate OIDC federated grants for annotation.
func TestClassifyWebIdentityTrust(t *testing.T) {
	tests := []struct {
		name, statement string
		want            bool
	}{
		{name: "exact", statement: `{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/issuer.example"},"Action":"sts:AssumeRoleWithWebIdentity"}`, want: true},
		{name: "mixed case action", statement: `{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/issuer.example"},"Action":"STS:assumerolewithwebidentity"}`, want: true},
		{name: "glob", statement: `{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/issuer.example"},"Action":"sts:AssumeRoleWith*"}`, want: true},
		{name: "array", statement: `{"Effect":"Allow","Principal":{"Federated":["arn:aws:iam::123456789012:saml-provider/example","arn:aws:iam::123456789012:oidc-provider/issuer.example"]},"Action":["sts:TagSession","sts:AssumeRoleWithWebIdentity"]}`, want: true},
		{name: "deny", statement: `{"Effect":"Deny","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/issuer.example"},"Action":"sts:AssumeRoleWithWebIdentity"}`},
		{name: "saml", statement: `{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:saml-provider/example"},"Action":"sts:AssumeRoleWithWebIdentity"}`},
		{name: "service", statement: `{"Effect":"Allow","Principal":{"Service":"pods.eks.amazonaws.com"},"Action":"sts:AssumeRoleWithWebIdentity"}`},
		{name: "unrelated action", statement: `{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/issuer.example"},"Action":"sts:AssumeRole"}`},
		{name: "non oidc resource", statement: `{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:role/example"},"Action":"sts:AssumeRoleWithWebIdentity"}`},
		{name: "not action", statement: `{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/issuer.example"},"NotAction":"sts:AssumeRole"}`},
		{name: "variable", statement: `{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/issuer.example"},"Action":"sts:${Operation}"}`},
		{name: "malformed action", statement: `{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/issuer.example"},"Action":42}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := url.QueryEscape(`{"Statement":` + tt.statement + `}`)
			if got := classifyWebIdentityTrust(&encoded); got != tt.want {
				t.Fatalf("classifyWebIdentityTrust() = %v, want %v", got, tt.want)
			}
		})
	}
}

// WO-109@v2: require the complete determinate EKS Pod Identity trust grant.
func TestClassifyPodIdentityTrust(t *testing.T) {
	tests := []struct {
		name, statement string
		want            bool
	}{
		{name: "canonical", statement: `{"Effect":"Allow","Principal":{"Service":"pods.eks.amazonaws.com"},"Action":["sts:AssumeRole","sts:TagSession"]}`, want: true},
		{name: "mixed case", statement: `{"Effect":"Allow","Principal":{"Service":"PODS.EKS.AMAZONAWS.COM"},"Action":["STS:ASSUMEROLE","STS:TAGSESSION"]}`, want: true},
		{name: "wildcard", statement: `{"Effect":"Allow","Principal":{"Service":"pods.eks.amazonaws.com"},"Action":"sts:*"}`, want: true},
		{name: "split statements", statement: `[{"Effect":"Allow","Principal":{"Service":"pods.eks.amazonaws.com"},"Action":"sts:AssumeRole"},{"Effect":"Allow","Principal":{"Service":"pods.eks.amazonaws.com"},"Action":"sts:TagSession"}]`, want: true},
		{name: "missing assume role", statement: `{"Effect":"Allow","Principal":{"Service":"pods.eks.amazonaws.com"},"Action":"sts:TagSession"}`},
		{name: "missing tag session", statement: `{"Effect":"Allow","Principal":{"Service":"pods.eks.amazonaws.com"},"Action":"sts:AssumeRole"}`},
		{name: "wrong service", statement: `{"Effect":"Allow","Principal":{"Service":"eks.amazonaws.com"},"Action":["sts:AssumeRole","sts:TagSession"]}`},
		{name: "deny", statement: `{"Effect":"Deny","Principal":{"Service":"pods.eks.amazonaws.com"},"Action":["sts:AssumeRole","sts:TagSession"]}`},
		{name: "not action", statement: `{"Effect":"Allow","Principal":{"Service":"pods.eks.amazonaws.com"},"NotAction":"s3:GetObject"}`},
		{name: "variable", statement: `{"Effect":"Allow","Principal":{"Service":"pods.eks.amazonaws.com"},"Action":["sts:AssumeRole","sts:${Operation}"]}`},
		{name: "malformed action", statement: `{"Effect":"Allow","Principal":{"Service":"pods.eks.amazonaws.com"},"Action":42}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := url.QueryEscape(`{"Statement":` + tt.statement + `}`)
			if got := classifyPodIdentityTrust(&encoded); got != tt.want {
				t.Fatalf("classifyPodIdentityTrust() = %v, want %v", got, tt.want)
			}
		})
	}
}

// WO-109@v2: Pod Identity metadata is deterministic and never changes finding presentation.
func TestRoleScanner_PodIdentityUnusedRolePolicy(t *testing.T) {
	podStatement := `{"Effect":"Allow","Principal":{"Service":"pods.eks.amazonaws.com"},"Action":["sts:AssumeRole","sts:TagSession"]}`
	webStatement := `{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/issuer.example"},"Action":"sts:AssumeRoleWithWebIdentity"}`
	tests := []struct {
		name       string
		statements string
		want       any
	}{
		{name: "pod identity", statements: podStatement, want: "pod_identity"},
		{name: "mixed trust prefers pod identity", statements: `[` + webStatement + `,` + podStatement + `]`, want: "pod_identity"},
		{name: "classic web identity", statements: webStatement, want: "web_identity"},
		{name: "ordinary trust", statements: `{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trust := url.QueryEscape(`{"Statement":` + tt.statements + `}`)
			stale := time.Now().UTC().AddDate(0, 0, -120)
			role := iamtypes.Role{
				RoleName:                 awssdk.String("candidate"),
				Arn:                      awssdk.String("arn:aws:iam::123456789012:role/candidate"),
				RoleLastUsed:             &iamtypes.RoleLastUsed{LastUsedDate: &stale},
				AssumeRolePolicyDocument: &trust,
			}
			result, err := NewRoleScanner(&mockIAM{roles: []iamtypes.Role{role}}, "123456789012").Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			finding := findFinding(result.Findings, iam.FindingUnusedRole)
			if finding == nil || finding.Severity != iam.SeverityMedium || finding.Recommendation != customerManagedRoleGuidance {
				t.Fatalf("finding presentation = %#v", finding)
			}
			if got := finding.Metadata["trust_mechanism"]; got != tt.want {
				t.Fatalf("trust_mechanism = %#v, want %#v", got, tt.want)
			}
		})
	}
}

// WO-54@v3: web-identity trust annotates known stale evidence without changing its presentation.
func TestRoleScanner_WebIdentityUnusedRolePolicy(t *testing.T) {
	trust := url.QueryEscape(`{"Statement":{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/issuer.example"},"Action":"sts:AssumeRoleWithWebIdentity"}}`)
	stale := time.Now().UTC().AddDate(0, 0, -120)
	roles := []iamtypes.Role{{RoleName: awssdk.String("stale-irsa"), Arn: awssdk.String("arn:aws:iam::123456789012:role/stale-irsa"), CreateDate: awssdk.Time(time.Now().UTC().AddDate(-2, 0, 0)), RoleLastUsed: &iamtypes.RoleLastUsed{LastUsedDate: &stale}, AssumeRolePolicyDocument: &trust}}

	result, err := NewRoleScanner(&mockIAM{roles: roles}, "123456789012").Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("default scan: %v", err)
	}
	finding := findFinding(result.Findings, iam.FindingUnusedRole)
	if finding == nil || finding.Severity != iam.SeverityMedium {
		t.Fatalf("finding = %#v, want unchanged medium UNUSED_ROLE", finding)
	}
	if finding.Message != "Role not assumed in 120 days" || finding.Recommendation != customerManagedRoleGuidance {
		t.Fatalf("presentation changed: %#v", finding)
	}
	if finding.Metadata["trust_mechanism"] != "web_identity" {
		t.Fatalf("metadata = %#v", finding.Metadata)
	}
}

// WO-54@v3: web-identity and ordinary roles share the same missing-evidence boundary.
// WO-104@v3: both roles merge into one account-scoped observation.
func TestRoleScanner_WebIdentityMissingUsageEvidence(t *testing.T) {
	trust := url.QueryEscape(`{"Statement":{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/issuer.example"},"Action":"sts:AssumeRoleWithWebIdentity"}}`)
	roles := []iamtypes.Role{
		{RoleName: awssdk.String("unknown-irsa"), Arn: awssdk.String("arn:aws:iam::123456789012:role/unknown-irsa"), CreateDate: awssdk.Time(time.Now().UTC().AddDate(-2, 0, 0)), AssumeRolePolicyDocument: &trust},
		{RoleName: awssdk.String("unknown-ordinary"), Arn: awssdk.String("arn:aws:iam::123456789012:role/unknown-ordinary"), CreateDate: awssdk.Time(time.Now().UTC().AddDate(-2, 0, 0))},
	}
	result, err := NewRoleScanner(&mockIAM{roles: roles}, "123456789012").Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if findFinding(result.Findings, iam.FindingUnusedRole) != nil {
		t.Fatal("missing usage evidence must not emit UNUSED_ROLE")
	}
	assertRoleUsageCoverage(t, result, 2, 0, 2)
}

// WO-107@v2: missing ListRoles evidence is enriched once without weakening the absence boundary.
func TestRoleScanner_EnrichesMissingUsageEvidence(t *testing.T) {
	stale := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	recent := time.Now().UTC().AddDate(0, 0, -1)
	tests := []struct {
		name         string
		getRole      func(context.Context, *iamsvc.GetRoleInput) (*iamsvc.GetRoleOutput, error)
		wantFinding  bool
		wantCoverage bool
		wantCause    string
	}{
		{
			name: "stale",
			getRole: func(context.Context, *iamsvc.GetRoleInput) (*iamsvc.GetRoleOutput, error) {
				return &iamsvc.GetRoleOutput{Role: &iamtypes.Role{RoleLastUsed: &iamtypes.RoleLastUsed{LastUsedDate: &stale}}}, nil
			},
			wantFinding: true,
		},
		{
			name: "recent",
			getRole: func(context.Context, *iamsvc.GetRoleInput) (*iamsvc.GetRoleOutput, error) {
				return &iamsvc.GetRoleOutput{Role: &iamtypes.Role{RoleLastUsed: &iamtypes.RoleLastUsed{LastUsedDate: &recent}}}, nil
			},
		},
		{
			name: "denied",
			getRole: func(context.Context, *iamsvc.GetRoleInput) (*iamsvc.GetRoleOutput, error) {
				return nil, codedAPIError{code: "AccessDenied"}
			},
			wantCoverage: true,
			wantCause:    "getrole_denied",
		},
		{
			name: "nil role",
			getRole: func(context.Context, *iamsvc.GetRoleInput) (*iamsvc.GetRoleOutput, error) {
				return &iamsvc.GetRoleOutput{}, nil
			},
			wantCoverage: true,
			wantCause:    "evidence_unavailable",
		},
		{
			name: "nil usage evidence",
			getRole: func(context.Context, *iamsvc.GetRoleInput) (*iamsvc.GetRoleOutput, error) {
				return &iamsvc.GetRoleOutput{Role: &iamtypes.Role{}}, nil
			},
			wantCoverage: true,
			wantCause:    "evidence_unavailable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role := iamtypes.Role{
				RoleName: awssdk.String("candidate"),
				Arn:      awssdk.String("arn:aws:iam::123456789012:role/candidate"),
			}
			mock := &mockIAM{roles: []iamtypes.Role{role}, getRoleFn: tt.getRole}
			result, err := NewRoleScanner(mock, "123456789012").Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if len(mock.getRoleCalls) != 1 || mock.getRoleCalls[0] != "candidate" {
				t.Fatalf("GetRole calls = %#v, want [candidate]", mock.getRoleCalls)
			}
			finding := findFinding(result.Findings, iam.FindingUnusedRole)
			if (finding != nil) != tt.wantFinding {
				t.Fatalf("UNUSED_ROLE = %#v, want finding=%t", finding, tt.wantFinding)
			}
			if tt.wantCoverage {
				assertRoleUsageCoverage(t, result, 1, 0, 1)
				if len(result.CoverageGapDetails) != 1 || result.CoverageGapDetails[0].Cause != tt.wantCause {
					t.Fatalf("coverage details = %#v, want cause=%q", result.CoverageGapDetails, tt.wantCause)
				}
			} else if len(result.CoverageGaps) != 0 {
				t.Fatalf("coverage gaps = %#v, want none", result.CoverageGaps)
			}
		})
	}
}

// WO-110@v5: codedAPIError supplies deterministic provider codes without SDK coupling.
type codedAPIError struct {
	code string // WO-110@v5: injected stable code for failure-classification fixtures.
}

// WO-110@v5: implement error text without leaking injected codes into log assertions.
func (e codedAPIError) Error() string {
	return "coded provider failure"
}

// WO-110@v5: expose the stable injected code through the production classifier seam.
func (e codedAPIError) ErrorCode() string {
	return e.code
}

// WO-110@v5: provider codes map to a closed, non-sensitive coverage cause set.
func TestClassifyGetRoleFailure(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "access denied", err: codedAPIError{code: "AccessDeniedException"}, want: "getrole_denied"},
		{name: "unauthorized operation", err: codedAPIError{code: "UnauthorizedOperation"}, want: "getrole_denied"},
		{name: "throttling", err: codedAPIError{code: "ThrottlingException"}, want: "getrole_throttled"},
		{name: "request limit", err: codedAPIError{code: "RequestLimitExceeded"}, want: "getrole_throttled"},
		{name: "wrapped", err: fmt.Errorf("request: %w", codedAPIError{code: "AccessDenied"}), want: "getrole_denied"},
		{name: "other code", err: codedAPIError{code: "ServiceFailure"}, want: "getrole_failed"},
		{name: "plain error", err: errors.New("provider marker"), want: "getrole_failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyGetRoleFailure(tt.err); got != tt.want {
				t.Fatalf("classifyGetRoleFailure() = %q, want %q", got, tt.want)
			}
		})
	}
}

// WO-110@v5: specific causes stay private while the legacy aggregate denominator remains singular.
func TestRoleScanner_CoverageGapCausesAndDetails(t *testing.T) {
	oldLogger := slog.Default()
	t.Cleanup(func() { slog.SetDefault(oldLogger) })
	var logs bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))

	roleNames := []string{"absent-role", "denied-role", "throttled-role", "failed-role"}
	roles := make([]iamtypes.Role, 0, len(roleNames))
	for _, roleName := range roleNames {
		roles = append(roles, iamtypes.Role{
			RoleName: awssdk.String(roleName),
			Arn:      awssdk.String("arn:aws:iam::123456789012:role/" + roleName),
		})
	}
	mock := &mockIAM{
		roles: roles,
		getRoleFn: func(_ context.Context, input *iamsvc.GetRoleInput) (*iamsvc.GetRoleOutput, error) {
			switch awssdk.ToString(input.RoleName) {
			case "absent-role":
				return &iamsvc.GetRoleOutput{Role: &iamtypes.Role{}}, nil
			case "denied-role":
				return nil, codedAPIError{code: "AccessDenied"}
			case "throttled-role":
				return nil, codedAPIError{code: "Throttling"}
			default:
				return nil, errors.New("provider marker must not be logged")
			}
		},
	}
	result, err := NewRoleScanner(mock, "123456789012").Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	wantCauses := []string{"evidence_unavailable", "getrole_denied", "getrole_throttled", "getrole_failed"}
	if len(result.CoverageGaps) != 1 {
		t.Fatalf("coverage gaps = %#v", result.CoverageGaps)
	}
	gap := result.CoverageGaps[0]
	if gap.Cause != "evidence_unavailable" || gap.AffectedCount != 4 || gap.EvaluableCount != 0 || gap.TotalCount != 4 {
		t.Fatalf("coverage gap = %#v, want one unchanged aggregate", gap)
	}
	if len(result.CoverageGapDetails) != len(roleNames) {
		t.Fatalf("coverage details = %#v", result.CoverageGapDetails)
	}
	for i, detail := range result.CoverageGapDetails {
		if detail.ResourceName != roleNames[i] || detail.Cause != wantCauses[i] ||
			detail.ResourceID != "arn:aws:iam::123456789012:role/"+roleNames[i] ||
			detail.ResourceType != iam.ResourceIAMRole || detail.Capability != "aws_role_last_used" {
			t.Fatalf("coverage detail[%d] = %#v", i, detail)
		}
	}
	logOutput := logs.String()
	for _, roleName := range roleNames {
		if !strings.Contains(logOutput, roleName) {
			t.Fatalf("debug output missing role %q: %s", roleName, logOutput)
		}
	}
	for _, cause := range wantCauses {
		if !strings.Contains(logOutput, "cause="+cause) {
			t.Fatalf("debug output missing cause %q: %s", cause, logOutput)
		}
	}
	if !strings.Contains(logOutput, "role_last_used_coverage_detail") || strings.Contains(logOutput, "provider marker") {
		t.Fatalf("debug output = %s", logOutput)
	}
}

// WO-107@v2: context cancellation remains a scan error rather than missing provider evidence.
func TestRoleScanner_GetRoleCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	mock := &mockIAM{
		roles: []iamtypes.Role{{RoleName: awssdk.String("candidate"), Arn: awssdk.String("arn:aws:iam::123456789012:role/candidate")}},
		getRoleFn: func(callCtx context.Context, _ *iamsvc.GetRoleInput) (*iamsvc.GetRoleOutput, error) {
			cancel()
			return nil, callCtx.Err()
		},
	}
	_, err := NewRoleScanner(mock, "123456789012").Scan(ctx, iam.ScanConfig{StaleDays: 90})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("scan error = %v, want context.Canceled", err)
	}
}

// WO-107@v2: opted-in service-linked roles may enrich but retain restrained presentation.
func TestRoleScanner_EnrichesIncludedServiceLinkedRole(t *testing.T) {
	stale := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	role := iamtypes.Role{
		RoleName: awssdk.String("AWSServiceRoleForExample"),
		Arn:      awssdk.String("arn:aws:iam::123456789012:role/aws-service-role/example.amazonaws.com/AWSServiceRoleForExample"),
		Path:     awssdk.String("/aws-service-role/example.amazonaws.com/"),
	}
	mock := &mockIAM{
		roles: []iamtypes.Role{role},
		getRoleFn: func(context.Context, *iamsvc.GetRoleInput) (*iamsvc.GetRoleOutput, error) {
			return &iamsvc.GetRoleOutput{Role: &iamtypes.Role{RoleLastUsed: &iamtypes.RoleLastUsed{LastUsedDate: &stale}}}, nil
		},
	}
	result, err := NewRoleScanner(mock, "123456789012").Scan(context.Background(), iam.ScanConfig{
		StaleDays:                 90,
		IncludeServiceLinkedRoles: true,
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	finding := findFinding(result.Findings, iam.FindingUnusedRole)
	if finding == nil || finding.Severity != iam.SeverityLow || !strings.Contains(finding.Recommendation, "owning AWS service") {
		t.Fatalf("finding = %#v, want low-severity service lifecycle guidance", finding)
	}
	if len(mock.getRoleCalls) != 1 || mock.getRoleCalls[0] != "AWSServiceRoleForExample" {
		t.Fatalf("GetRole calls = %#v", mock.getRoleCalls)
	}
}

// WO-107@v2: enrichment replaces only usage evidence, preserving trust-derived metadata from ListRoles.
func TestRoleScanner_EnrichedWebIdentityRetainsListTrust(t *testing.T) {
	stale := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	trust := url.QueryEscape(`{"Statement":{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/issuer.example"},"Action":"sts:AssumeRoleWithWebIdentity"}}`)
	role := iamtypes.Role{
		RoleName:                 awssdk.String("web-identity"),
		Arn:                      awssdk.String("arn:aws:iam::123456789012:role/web-identity"),
		RoleLastUsed:             &iamtypes.RoleLastUsed{},
		AssumeRolePolicyDocument: &trust,
	}
	mock := &mockIAM{
		roles: []iamtypes.Role{role},
		getRoleFn: func(context.Context, *iamsvc.GetRoleInput) (*iamsvc.GetRoleOutput, error) {
			return &iamsvc.GetRoleOutput{Role: &iamtypes.Role{RoleLastUsed: &iamtypes.RoleLastUsed{LastUsedDate: &stale}}}, nil
		},
	}
	result, err := NewRoleScanner(mock, "123456789012").Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	finding := findFinding(result.Findings, iam.FindingUnusedRole)
	if finding == nil || finding.Metadata["trust_mechanism"] != "web_identity" {
		t.Fatalf("finding metadata = %#v, want web_identity", finding)
	}
	if len(mock.getRoleCalls) != 1 || mock.getRoleCalls[0] != "web-identity" {
		t.Fatalf("GetRole calls = %#v", mock.getRoleCalls)
	}
}

// WO-104@v3: excluded and default-suppressed roles cannot inflate coverage denominators.
// WO-107@v2: only the eligible role with missing list evidence may call GetRole.
func TestRoleScanner_RoleUsageCoverageCountsEligibleRoles(t *testing.T) {
	recent := time.Now().UTC().AddDate(0, 0, -1)
	stale := time.Now().UTC().AddDate(0, 0, -120)
	roles := []iamtypes.Role{
		{RoleName: awssdk.String("unknown"), Arn: awssdk.String("arn:aws:iam::123456789012:role/unknown")},
		{RoleName: awssdk.String("recent"), Arn: awssdk.String("arn:aws:iam::123456789012:role/recent"), RoleLastUsed: &iamtypes.RoleLastUsed{LastUsedDate: &recent}},
		{RoleName: awssdk.String("stale"), Arn: awssdk.String("arn:aws:iam::123456789012:role/stale"), RoleLastUsed: &iamtypes.RoleLastUsed{LastUsedDate: &stale}},
		{RoleName: awssdk.String("excluded"), Arn: awssdk.String("arn:aws:iam::123456789012:role/excluded")},
		{
			RoleName: awssdk.String("AWSServiceRoleForExample"),
			Arn:      awssdk.String("arn:aws:iam::123456789012:role/aws-service-role/example.amazonaws.com/AWSServiceRoleForExample"),
			Path:     awssdk.String("/aws-service-role/example.amazonaws.com/"),
		},
	}
	cfg := iam.ScanConfig{StaleDays: 90, Exclude: iam.ExcludeConfig{Principals: map[string]bool{"excluded": true}}}
	mock := &mockIAM{roles: roles}
	result, err := NewRoleScanner(mock, "123456789012").Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	assertRoleUsageCoverage(t, result, 1, 2, 3)
	if finding := findFinding(result.Findings, iam.FindingUnusedRole); finding == nil || finding.ResourceName != "stale" {
		t.Fatalf("findings = %#v, want only stale role usage finding", result.Findings)
	}
	if strings.Join(mock.getRoleCalls, ",") != "unknown" {
		t.Fatalf("GetRole calls = %#v, want only unknown", mock.getRoleCalls)
	}
}

func TestRoleScanner_CrossAccountTrust(t *testing.T) {
	trustPolicy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":"sts:AssumeRole"}]}`
	encodedTrust := url.QueryEscape(trustPolicy)

	mock := &mockIAM{
		roles: []iamtypes.Role{
			{
				RoleName:                 awssdk.String("cross-acct-role"),
				Arn:                      awssdk.String("arn:aws:iam::123456789012:role/cross-acct-role"),
				Path:                     awssdk.String("/"),
				CreateDate:               awssdk.Time(time.Now().UTC().AddDate(0, 0, -10)),
				RoleLastUsed:             &iamtypes.RoleLastUsed{LastUsedDate: awssdk.Time(time.Now().UTC().AddDate(0, 0, -1))},
				AssumeRolePolicyDocument: awssdk.String(encodedTrust),
			},
		},
	}

	scanner := NewRoleScanner(mock, "123456789012")
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	found := findFinding(result.Findings, iam.FindingCrossAccountTrust)
	if found == nil {
		t.Fatal("expected CROSS_ACCOUNT_TRUST finding")
	}
	if found.Severity != iam.SeverityCritical {
		t.Fatalf("expected critical severity, got %s", found.Severity)
	}
}

func TestRoleScanner_CrossAccountTrustWithCondition(t *testing.T) {
	trustPolicy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"secret123"}}}]}`
	encodedTrust := url.QueryEscape(trustPolicy)

	mock := &mockIAM{
		roles: []iamtypes.Role{
			{
				RoleName:                 awssdk.String("safe-cross-acct"),
				Arn:                      awssdk.String("arn:aws:iam::123456789012:role/safe-cross-acct"),
				Path:                     awssdk.String("/"),
				CreateDate:               awssdk.Time(time.Now().UTC().AddDate(0, 0, -10)),
				RoleLastUsed:             &iamtypes.RoleLastUsed{LastUsedDate: awssdk.Time(time.Now().UTC().AddDate(0, 0, -1))},
				AssumeRolePolicyDocument: awssdk.String(encodedTrust),
			},
		},
	}

	scanner := NewRoleScanner(mock, "123456789012")
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	// Should NOT have cross-account finding since it has a condition
	found := findFinding(result.Findings, iam.FindingCrossAccountTrust)
	if found != nil {
		t.Fatal("expected no CROSS_ACCOUNT_TRUST finding when conditions present")
	}
}

func TestRoleScanner_SameAccountTrust(t *testing.T) {
	trustPolicy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}]}`
	encodedTrust := url.QueryEscape(trustPolicy)

	mock := &mockIAM{
		roles: []iamtypes.Role{
			{
				RoleName:                 awssdk.String("same-acct-role"),
				Arn:                      awssdk.String("arn:aws:iam::123456789012:role/same-acct-role"),
				Path:                     awssdk.String("/"),
				CreateDate:               awssdk.Time(time.Now().UTC().AddDate(0, 0, -10)),
				RoleLastUsed:             &iamtypes.RoleLastUsed{LastUsedDate: awssdk.Time(time.Now().UTC().AddDate(0, 0, -1))},
				AssumeRolePolicyDocument: awssdk.String(encodedTrust),
			},
		},
	}

	scanner := NewRoleScanner(mock, "123456789012")
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	found := findFinding(result.Findings, iam.FindingCrossAccountTrust)
	if found != nil {
		t.Fatal("expected no CROSS_ACCOUNT_TRUST for same-account trust")
	}
}

func TestRoleScanner_Excluded(t *testing.T) {
	mock := &mockIAM{
		roles: []iamtypes.Role{
			{
				RoleName:     awssdk.String("excluded-role"),
				Arn:          awssdk.String("arn:aws:iam::123456789012:role/excluded-role"),
				Path:         awssdk.String("/"),
				CreateDate:   awssdk.Time(time.Now().UTC().AddDate(-2, 0, 0)),
				RoleLastUsed: nil,
			},
		},
	}

	cfg := iam.ScanConfig{
		StaleDays: 90,
		Exclude: iam.ExcludeConfig{
			Principals: map[string]bool{"excluded-role": true},
		},
	}

	scanner := NewRoleScanner(mock, "123456789012")
	result, err := scanner.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for excluded role, got %d", len(result.Findings))
	}
}

func TestRoleScanner_Type(t *testing.T) {
	scanner := NewRoleScanner(nil, "")
	if scanner.Type() != iam.ResourceIAMRole {
		t.Fatalf("expected %s, got %s", iam.ResourceIAMRole, scanner.Type())
	}
}

func TestRoleScanner_ListError(t *testing.T) {
	mock := &mockIAM{
		rolesErr: context.DeadlineExceeded,
	}

	scanner := NewRoleScanner(mock, "123456789012")
	_, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestIsExternalAccount(t *testing.T) {
	scanner := &RoleScanner{accountID: "123456789012"}

	tests := []struct {
		principal string
		external  bool
	}{
		{"*", true},
		{"arn:aws:iam::123456789012:root", false},
		{"arn:aws:iam::999999999999:root", true},
		{"arn:aws:iam::999999999999:role/some-role", true},
		{"not-an-arn", false},
	}

	for _, tt := range tests {
		t.Run(tt.principal, func(t *testing.T) {
			got := scanner.isExternalAccount(tt.principal)
			if got != tt.external {
				t.Fatalf("isExternalAccount(%q) = %v, want %v", tt.principal, got, tt.external)
			}
		})
	}
}

// WO-19@v3: concrete external trust must fail open unless its condition is provably bounded.
func TestRoleScanner_CrossAccountTrustConditionClassification(t *testing.T) {
	tests := []struct {
		name      string
		condition string
		want      bool
	}{
		{"bounded external id suppresses", `,"Condition":{"StringEquals":{"sts:ExternalId":"customer-123"}}`, false},
		{"inverted condition emits", `,"Condition":{"StringNotEquals":{"sts:ExternalId":"customer-123"}}`, true},
		{"wildcard value emits", `,"Condition":{"StringEquals":{"sts:ExternalId":"*"}}`, true},
		{"malformed value emits", `,"Condition":{"StringEquals":{"sts:ExternalId":42}}`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":"sts:AssumeRole"` + tt.condition + `}]}`
			if got := hasCrossAccountTrustFinding(t, policy); got != tt.want {
				t.Fatalf("finding = %v, want %v", got, tt.want)
			}
		})
	}
}

// WO-37@v2: literal wildcard trust follows the same bounded-condition gate as concrete principals.
func TestRoleScanner_WildcardPrincipalTrust(t *testing.T) {
	tests := []struct {
		name      string
		condition string
		want      bool
	}{
		{"unconditioned emits", ``, true},
		{"bounded condition suppresses", `,"Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-1234567890"}}`, false},
		{"inverted condition emits", `,"Condition":{"StringNotEquals":{"aws:PrincipalOrgID":"o-1234567890"}}`, true},
		{"empty condition emits", `,"Condition":{}`, true},
		{"malformed condition emits", `,"Condition":{"StringEquals":{"sts:ExternalId":42}}`, true},
		{"wildcard condition emits", `,"Condition":{"StringEquals":{"sts:ExternalId":"customer-*"}}`, true},
		{"universal network emits", `,"Condition":{"IpAddress":{"aws:SourceIp":"0.0.0.0/0"}}`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"` + tt.condition + `}]}`
			if got := hasCrossAccountTrustFinding(t, policy); got != tt.want {
				t.Fatalf("finding = %v, want %v", got, tt.want)
			}
		})
	}
}

// WO-40: scanner findings require an action that actually grants sts:AssumeRole.
func TestRoleScanner_CrossAccountTrustActionClassification(t *testing.T) {
	tests := []struct {
		name   string
		action string
		want   bool
	}{
		{"exact", `"sts:AssumeRole"`, true},
		{"case insensitive", `"STS:ASSUMEROLE"`, true},
		{"matching pattern", `"sts:Assume*"`, true},
		{"matching list", `["sts:TagSession","sts:AssumeRole"]`, true},
		{"unrelated", `"s3:GetObject"`, false},
		{"tag session", `"sts:TagSession"`, false},
		{"saml", `"sts:AssumeRoleWithSAML"`, false},
		{"web identity", `"sts:AssumeRoleWithWebIdentity"`, false},
		{"nonmatching list", `["sts:TagSession","sts:AssumeRoleWithSAML"]`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":` + tt.action + `}]}`
			if got := hasCrossAccountTrustFinding(t, policy); got != tt.want {
				t.Fatalf("finding = %v, want %v", got, tt.want)
			}
		})
	}
}

// WO-37@v2: exercise trust classification directly without scanner setup noise.
func hasCrossAccountTrustFinding(t *testing.T, policy string) bool {
	t.Helper()
	result := &iam.ScanResult{}
	scanner := &RoleScanner{accountID: "123456789012"}
	encoded := url.QueryEscape(policy)
	scanner.checkCrossAccountTrust(&encoded, "arn:aws:iam::123456789012:role/test", "test", result)
	return findFinding(result.Findings, iam.FindingCrossAccountTrust) != nil
}
