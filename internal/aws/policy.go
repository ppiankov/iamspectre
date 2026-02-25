package aws

import (
	"context"
	"fmt"
	"log/slog"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	iamsvc "github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/ppiankov/iamspectre/internal/iam"
)

// PolicyScanner detects unattached and wildcard IAM policies.
type PolicyScanner struct {
	client IAMAPI
}

// NewPolicyScanner creates a scanner for IAM policies.
func NewPolicyScanner(client IAMAPI) *PolicyScanner {
	return &PolicyScanner{client: client}
}

// Type returns the resource type this scanner handles.
func (s *PolicyScanner) Type() iam.ResourceType {
	return iam.ResourceIAMPolicy
}

// Scan examines customer-managed IAM policies for issues.
func (s *PolicyScanner) Scan(ctx context.Context, cfg iam.ScanConfig) (*iam.ScanResult, error) {
	policies, err := s.listPolicies(ctx)
	if err != nil {
		return nil, err
	}

	result := &iam.ScanResult{PrincipalsScanned: len(policies)}

	for _, policy := range policies {
		policyARN := awssdk.ToString(policy.Arn)
		policyName := awssdk.ToString(policy.PolicyName)

		if isExcluded(cfg, policyARN, policyName) {
			continue
		}

		// Check unattached policy
		if policy.AttachmentCount != nil && *policy.AttachmentCount == 0 {
			result.Findings = append(result.Findings, iam.Finding{
				ID:             iam.FindingUnattachedPolicy,
				Severity:       iam.SeverityMedium,
				ResourceType:   iam.ResourceIAMPolicy,
				ResourceID:     policyARN,
				ResourceName:   policyName,
				Message:        "Customer-managed policy not attached to any user, group, or role",
				Recommendation: "Delete the policy if no longer needed",
				Metadata: map[string]any{
					"attachment_count": 0,
				},
			})
			continue // No need to check document for unattached policy
		}

		// Check for wildcard permissions in the active policy version
		s.checkWildcardPolicy(ctx, policy, policyARN, policyName, result)
	}

	return result, nil
}

func (s *PolicyScanner) checkWildcardPolicy(ctx context.Context, policy iamtypes.Policy, policyARN, policyName string, result *iam.ScanResult) {
	if policy.DefaultVersionId == nil {
		return
	}

	out, err := s.client.GetPolicyVersion(ctx, &iamsvc.GetPolicyVersionInput{
		PolicyArn: policy.Arn,
		VersionId: policy.DefaultVersionId,
	})
	if err != nil {
		slog.Warn("Failed to get policy version", "policy", policyName, "error", err)
		result.Errors = append(result.Errors, fmt.Sprintf("get policy version %s: %v", policyName, err))
		return
	}

	if out.PolicyVersion == nil || out.PolicyVersion.Document == nil {
		return
	}

	doc, err := ParsePolicyDocument(*out.PolicyVersion.Document)
	if err != nil {
		slog.Warn("Failed to parse policy document", "policy", policyName, "error", err)
		return
	}

	if doc.HasWildcardAction() || doc.HasWildcardResource() {
		wildcardType := "resource"
		if doc.HasWildcardAction() {
			wildcardType = "action"
		}
		if doc.HasWildcardAction() && doc.HasWildcardResource() {
			wildcardType = "action and resource"
		}

		result.Findings = append(result.Findings, iam.Finding{
			ID:             iam.FindingWildcardPolicy,
			Severity:       iam.SeverityCritical,
			ResourceType:   iam.ResourceIAMPolicy,
			ResourceID:     policyARN,
			ResourceName:   policyName,
			Message:        fmt.Sprintf("Policy has wildcard %s permissions", wildcardType),
			Recommendation: "Restrict policy to specific actions and resources following least-privilege principle",
			Metadata: map[string]any{
				"wildcard_action":   doc.HasWildcardAction(),
				"wildcard_resource": doc.HasWildcardResource(),
				"attachment_count":  awssdk.ToInt32(policy.AttachmentCount),
			},
		})
	}
}

func (s *PolicyScanner) listPolicies(ctx context.Context) ([]iamtypes.Policy, error) {
	var policies []iamtypes.Policy
	var marker *string

	for {
		out, err := s.client.ListPolicies(ctx, &iamsvc.ListPoliciesInput{
			Scope:    iamtypes.PolicyScopeTypeLocal, // Customer-managed only
			Marker:   marker,
			MaxItems: awssdk.Int32(100),
		})
		if err != nil {
			return nil, fmt.Errorf("list IAM policies: %w", err)
		}

		policies = append(policies, out.Policies...)

		if !out.IsTruncated {
			break
		}
		marker = out.Marker
	}

	slog.Debug("Listed IAM policies", "count", len(policies))
	return policies, nil
}
