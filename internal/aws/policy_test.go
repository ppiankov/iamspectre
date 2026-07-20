package aws

import (
	"context"
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
