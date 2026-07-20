package aws

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	iamsvc "github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/ppiankov/iamspectre/internal/iam"
)

func TestPolicyScanner_UnattachedPolicy(t *testing.T) {
	mock := &mockIAM{
		policies: []iamtypes.Policy{
			{
				PolicyName:      awssdk.String("orphan-policy"),
				Arn:             awssdk.String("arn:aws:iam::123456789012:policy/orphan-policy"),
				AttachmentCount: awssdk.Int32(0),
			},
		},
	}

	scanner := NewPolicyScanner(mock)
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	found := findFinding(result.Findings, iam.FindingUnattachedPolicy)
	if found == nil {
		t.Fatal("expected UNATTACHED_POLICY finding")
	}
	if found.Severity != iam.SeverityMedium {
		t.Fatalf("expected medium severity, got %s", found.Severity)
	}
}

func TestPolicyScanner_WildcardActionPolicy(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"arn:aws:s3:::my-bucket"}]}`
	encodedDoc := url.QueryEscape(doc)

	mock := &mockIAM{
		policies: []iamtypes.Policy{
			{
				PolicyName:       awssdk.String("admin-policy"),
				Arn:              awssdk.String("arn:aws:iam::123456789012:policy/admin-policy"),
				AttachmentCount:  awssdk.Int32(1),
				DefaultVersionId: awssdk.String("v1"),
			},
		},
		policyVersion: &iamsvc.GetPolicyVersionOutput{
			PolicyVersion: &iamtypes.PolicyVersion{
				Document: awssdk.String(encodedDoc),
			},
		},
	}

	scanner := NewPolicyScanner(mock)
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	found := findFinding(result.Findings, iam.FindingWildcardPolicy)
	if found == nil {
		t.Fatal("expected WILDCARD_POLICY finding")
	}
	if found.Severity != iam.SeverityCritical {
		t.Fatalf("expected critical severity, got %s", found.Severity)
	}
}

func TestPolicyScanner_WildcardResourcePolicy(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`
	encodedDoc := url.QueryEscape(doc)

	mock := &mockIAM{
		policies: []iamtypes.Policy{
			{
				PolicyName:       awssdk.String("broad-policy"),
				Arn:              awssdk.String("arn:aws:iam::123456789012:policy/broad-policy"),
				AttachmentCount:  awssdk.Int32(2),
				DefaultVersionId: awssdk.String("v1"),
			},
		},
		policyVersion: &iamsvc.GetPolicyVersionOutput{
			PolicyVersion: &iamtypes.PolicyVersion{
				Document: awssdk.String(encodedDoc),
			},
		},
	}

	scanner := NewPolicyScanner(mock)
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	found := findFinding(result.Findings, iam.FindingWildcardPolicy)
	if found == nil {
		t.Fatal("expected WILDCARD_POLICY finding for wildcard resource")
	}
}

// WO-66@v2: proved bounded conditions lower resource breadth without suppressing it.
func TestPolicyScanner_BoundedWildcardResourcePolicy(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":"192.0.2.0/24"}}}]}`
	mock := &mockIAM{
		policies: []iamtypes.Policy{{
			PolicyName: awssdk.String("bounded-policy"), Arn: awssdk.String("arn:aws:iam::123456789012:policy/bounded-policy"),
			AttachmentCount: awssdk.Int32(1), DefaultVersionId: awssdk.String("v1"),
		}},
		policyVersion: &iamsvc.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{
			Document: awssdk.String(url.QueryEscape(doc)),
		}},
	}

	result, err := NewPolicyScanner(mock).Scan(context.Background(), iam.ScanConfig{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	finding := findFinding(result.Findings, iam.FindingWildcardPolicy)
	if finding == nil || finding.Severity != iam.SeverityHigh {
		t.Fatalf("finding = %#v, want retained high-severity wildcard finding", finding)
	}
	if finding.Metadata["condition_boundedness"] != string(ConditionBounded) {
		t.Fatalf("metadata = %#v, want bounded condition state", finding.Metadata)
	}
}

// WO-66@v2: unsupported conditions preserve observed wildcard severity and record uncertainty.
func TestPolicyScanner_IndeterminateConditionPreservesWildcardSeverity(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"StringEqualsIfExists":{"aws:SourceAccount":"123456789012"}}}]}`
	mock := &mockIAM{
		policies:      []iamtypes.Policy{{PolicyName: awssdk.String("uncertain-policy"), Arn: awssdk.String("arn:aws:iam::123456789012:policy/uncertain-policy"), AttachmentCount: awssdk.Int32(1), DefaultVersionId: awssdk.String("v1")}},
		policyVersion: &iamsvc.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{Document: awssdk.String(url.QueryEscape(doc))}},
	}
	result, err := NewPolicyScanner(mock).Scan(context.Background(), iam.ScanConfig{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	finding := findFinding(result.Findings, iam.FindingWildcardPolicy)
	if finding == nil || finding.Severity != iam.SeverityCritical {
		t.Fatalf("finding = %#v, want retained critical finding", finding)
	}
	if finding.Metadata["condition_boundedness"] != string(ConditionIndeterminate) {
		t.Fatalf("metadata = %#v, want indeterminate condition state", finding.Metadata)
	}
}

// WO-66@v2: conditions cannot lower action-wildcard severity.
func TestPolicyScanner_BoundedConditionDoesNotLowerWildcardAction(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringEquals":{"aws:SourceAccount":"123456789012"}}}]}`
	mock := &mockIAM{
		policies:      []iamtypes.Policy{{PolicyName: awssdk.String("admin-policy"), Arn: awssdk.String("arn:aws:iam::123456789012:policy/admin-policy"), AttachmentCount: awssdk.Int32(1), DefaultVersionId: awssdk.String("v1")}},
		policyVersion: &iamsvc.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{Document: awssdk.String(url.QueryEscape(doc))}},
	}
	result, err := NewPolicyScanner(mock).Scan(context.Background(), iam.ScanConfig{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	finding := findFinding(result.Findings, iam.FindingWildcardPolicy)
	if finding == nil || finding.Severity != iam.SeverityCritical {
		t.Fatalf("finding = %#v, want critical action-wildcard finding", finding)
	}
}

// WO-65@v2: Resource:* is not broad when every exact action supports no resource type.
func TestPolicyScanner_NoResourceActionsNeutralizeWildcardResource(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Action":"ssm:DescribeActivations","Resource":"*"}]}`
	result := scanPolicyDocument(t, "no-resource-policy", doc)
	if finding := findFinding(result.Findings, iam.FindingWildcardPolicy); finding != nil {
		t.Fatalf("unexpected wildcard finding: %#v", finding)
	}
}

// WO-65@v2: complementary resource syntax cannot neutralize an observed Resource wildcard.
func TestPolicyScanner_NotResourcePreservesWildcardResource(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Action":"ssm:DescribeActivations","Resource":"*","NotResource":"arn:aws:ssm:*:*:document/safe"}]}`
	result := scanPolicyDocument(t, "complementary-resource", doc)
	finding := findFinding(result.Findings, iam.FindingWildcardPolicy)
	if finding == nil || finding.Metadata["resource_applicability"] != string(ResourceApplicabilityIndeterminate) {
		t.Fatalf("finding = %#v, want preserved wildcard with indeterminate applicability", finding)
	}
}

// WO-65@v2: an invalid generated enum is uncertainty, never no-resource proof.
func TestPolicyDocument_InvalidCatalogApplicabilityIsIndeterminate(t *testing.T) {
	const action = "ssm:DescribeActivations"
	original := resourceApplicabilityCatalog[action]
	resourceApplicabilityCatalog[action] = ResourceApplicability("invalid")
	t.Cleanup(func() { resourceApplicabilityCatalog[action] = original })

	doc, err := ParsePolicyDocument(url.QueryEscape(`{"Statement":[{"Effect":"Allow","Action":"ssm:DescribeActivations","Resource":"*"}]}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	assessment := doc.AssessResourceApplicability()
	if assessment.State != ResourceApplicabilityIndeterminate {
		t.Fatalf("assessment = %#v, want indeterminate", assessment)
	}
}

// WO-65@v2: supported and unknown action evidence preserves the observed resource breadth.
func TestPolicyScanner_ResourceApplicabilityPreservesWildcard(t *testing.T) {
	tests := []struct {
		name      string
		action    string
		wantState ResourceApplicabilityAssessmentState
	}{
		{"supported", "ssm:GetDocument", ResourceApplicabilityDeterminate},
		{"unknown", "ssm:UnknownAction", ResourceApplicabilityIndeterminate},
		{"glob", "ssm:Describe*", ResourceApplicabilityIndeterminate},
		{"mixed", `["ssm:DescribeActivations","ssm:GetDocument"]`, ResourceApplicabilityDeterminate},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actionJSON := fmt.Sprintf("%q", tt.action)
			if strings.HasPrefix(tt.action, "[") {
				actionJSON = tt.action
			}
			doc := fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":%s,"Resource":"*"}]}`, actionJSON)
			result := scanPolicyDocument(t, tt.name, doc)
			finding := findFinding(result.Findings, iam.FindingWildcardPolicy)
			if finding == nil {
				t.Fatal("expected wildcard finding")
			}
			if finding.Metadata["resource_applicability"] != string(tt.wantState) {
				t.Fatalf("metadata = %#v, want state %s", finding.Metadata, tt.wantState)
			}
			if finding.Metadata["resource_applicability_catalog_digest"] == "" {
				t.Fatalf("metadata = %#v, want catalog digest", finding.Metadata)
			}
		})
	}
}

// WO-65@v2: mandatory Resource:* never hides an action wildcard.
func TestPolicyScanner_NoResourceActionWildcardRemainsFinding(t *testing.T) {
	result := scanPolicyDocument(t, "action-wildcard", `{"Statement":[{"Effect":"Allow","Action":"ssm:*","Resource":"*"}]}`)
	finding := findFinding(result.Findings, iam.FindingWildcardPolicy)
	if finding == nil || finding.Metadata["wildcard_action"] != true {
		t.Fatalf("finding = %#v, want action wildcard", finding)
	}
}

// WO-65@v2: build a customer-managed policy fixture around one encoded document.
func scanPolicyDocument(t *testing.T, name, document string) *iam.ScanResult {
	t.Helper()
	mock := &mockIAM{
		policies:      []iamtypes.Policy{{PolicyName: awssdk.String(name), Arn: awssdk.String("arn:aws:iam::123456789012:policy/" + name), AttachmentCount: awssdk.Int32(1), DefaultVersionId: awssdk.String("v1")}},
		policyVersion: &iamsvc.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{Document: awssdk.String(url.QueryEscape(document))}},
	}
	result, err := NewPolicyScanner(mock).Scan(context.Background(), iam.ScanConfig{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return result
}

func TestPolicyScanner_SafePolicy(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::my-bucket/*"}]}`
	encodedDoc := url.QueryEscape(doc)

	mock := &mockIAM{
		policies: []iamtypes.Policy{
			{
				PolicyName:       awssdk.String("safe-policy"),
				Arn:              awssdk.String("arn:aws:iam::123456789012:policy/safe-policy"),
				AttachmentCount:  awssdk.Int32(1),
				DefaultVersionId: awssdk.String("v1"),
			},
		},
		policyVersion: &iamsvc.GetPolicyVersionOutput{
			PolicyVersion: &iamtypes.PolicyVersion{
				Document: awssdk.String(encodedDoc),
			},
		},
	}

	scanner := NewPolicyScanner(mock)
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for safe policy, got %d", len(result.Findings))
	}
}

// WO-46: malformed managed policies must be present in reportable scan errors.
func TestPolicyScanner_ParseError(t *testing.T) {
	mock := &mockIAM{
		policies: []iamtypes.Policy{
			{
				PolicyName:       awssdk.String("bad-policy"),
				Arn:              awssdk.String("arn:aws:iam::123456789012:policy/bad-policy"),
				AttachmentCount:  awssdk.Int32(1),
				DefaultVersionId: awssdk.String("v1"),
			},
			{
				PolicyName:      awssdk.String("later-policy"),
				Arn:             awssdk.String("arn:aws:iam::123456789012:policy/later-policy"),
				AttachmentCount: awssdk.Int32(0),
			},
		},
		policyVersion: &iamsvc.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{
			Document: awssdk.String(url.QueryEscape(`{"Statement":42}`)),
		}},
	}
	result, err := NewPolicyScanner(mock).Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(result.Errors) != 1 || !strings.Contains(result.Errors[0], "bad-policy") ||
		!strings.Contains(result.Errors[0], "expected object or array") {
		t.Fatalf("errors = %#v, want one policy-qualified parse error", result.Errors)
	}
	if findFinding(result.Findings, iam.FindingUnattachedPolicy) == nil {
		t.Fatal("expected scanning to continue after malformed policy")
	}
}

// WO-41@v2: valid object-form policies reach statement-level detection.
// WO-46: accepted policy shapes must not fabricate parse errors.
func TestPolicyScanner_SingleStatementObject(t *testing.T) {
	doc := `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`
	mock := &mockIAM{
		policies: []iamtypes.Policy{{
			PolicyName: awssdk.String("object-policy"), Arn: awssdk.String("arn:aws:iam::123456789012:policy/object-policy"),
			AttachmentCount: awssdk.Int32(1), DefaultVersionId: awssdk.String("v1"),
		}},
		policyVersion: &iamsvc.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{
			Document: awssdk.String(url.QueryEscape(doc)),
		}},
	}
	result, err := NewPolicyScanner(mock).Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(result.Errors) != 0 || findFinding(result.Findings, iam.FindingWildcardPolicy) == nil {
		t.Fatalf("result = %#v, want wildcard finding without errors", result)
	}
}

func TestPolicyScanner_DenyStatementIgnored(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`
	encodedDoc := url.QueryEscape(doc)

	mock := &mockIAM{
		policies: []iamtypes.Policy{
			{
				PolicyName:       awssdk.String("deny-policy"),
				Arn:              awssdk.String("arn:aws:iam::123456789012:policy/deny-policy"),
				AttachmentCount:  awssdk.Int32(1),
				DefaultVersionId: awssdk.String("v1"),
			},
		},
		policyVersion: &iamsvc.GetPolicyVersionOutput{
			PolicyVersion: &iamtypes.PolicyVersion{
				Document: awssdk.String(encodedDoc),
			},
		},
	}

	scanner := NewPolicyScanner(mock)
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	// Deny with wildcard should NOT be flagged
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for Deny wildcard, got %d", len(result.Findings))
	}
}

func TestPolicyScanner_Excluded(t *testing.T) {
	mock := &mockIAM{
		policies: []iamtypes.Policy{
			{
				PolicyName:      awssdk.String("excluded-policy"),
				Arn:             awssdk.String("arn:aws:iam::123456789012:policy/excluded-policy"),
				AttachmentCount: awssdk.Int32(0),
			},
		},
	}

	cfg := iam.ScanConfig{
		StaleDays: 90,
		Exclude: iam.ExcludeConfig{
			Principals: map[string]bool{"excluded-policy": true},
		},
	}

	scanner := NewPolicyScanner(mock)
	result, err := scanner.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for excluded policy, got %d", len(result.Findings))
	}
}

func TestPolicyScanner_NoPolicies(t *testing.T) {
	mock := &mockIAM{
		policies: nil,
	}

	scanner := NewPolicyScanner(mock)
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(result.Findings))
	}
}

func TestPolicyScanner_Type(t *testing.T) {
	scanner := NewPolicyScanner(nil)
	if scanner.Type() != iam.ResourceIAMPolicy {
		t.Fatalf("expected %s, got %s", iam.ResourceIAMPolicy, scanner.Type())
	}
}

func TestPolicyScanner_ListError(t *testing.T) {
	mock := &mockIAM{
		policiesErr: context.DeadlineExceeded,
	}

	scanner := NewPolicyScanner(mock)
	_, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err == nil {
		t.Fatal("expected error")
	}
}
