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

		if iam.IsExcluded(cfg, policyARN, policyName) { // WO-14@v3: use the shared exclusion policy.
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
		result.Errors = append(result.Errors, fmt.Sprintf("parse policy document %s: %v", policyName, err)) // WO-46: report lost scan coverage.
		return
	}

	wildcardAction := doc.HasWildcardAction()
	wildcardResource := doc.HasWildcardResource()
	resourceApplicability := doc.AssessResourceApplicability()
	if resourceApplicability.State == ResourceApplicabilityDeterminate && resourceApplicability.AllNone {
		wildcardResource = false // WO-65@v2: Resource:* is mandatory syntax for actions with no resource type.
	}

	if wildcardAction || wildcardResource {
		condition := doc.AssessConditionBoundedness()
		wildcardType := "resource"
		if wildcardAction {
			wildcardType = "action"
		}
		if wildcardAction && wildcardResource {
			wildcardType = "action and resource"
		}

		severity := iam.SeverityCritical
		if !wildcardAction && condition.State == ConditionBounded {
			severity = iam.SeverityHigh // WO-66@v2: a proved condition bound lowers only resource breadth.
		}

		result.Findings = append(result.Findings, iam.Finding{
			ID:             iam.FindingWildcardPolicy,
			Severity:       severity,
			ResourceType:   iam.ResourceIAMPolicy,
			ResourceID:     policyARN,
			ResourceName:   policyName,
			Message:        fmt.Sprintf("Policy has wildcard %s permissions", wildcardType),
			Recommendation: "Restrict policy to specific actions and resources following least-privilege principle",
			Metadata: map[string]any{
				"wildcard_action":                       wildcardAction,
				"wildcard_resource":                     wildcardResource,
				"attachment_count":                      awssdk.ToInt32(policy.AttachmentCount),
				"condition_boundedness":                 string(condition.State),             // WO-66@v2: retain decision evidence.
				"condition_reason":                      condition.Reason,                    // WO-66@v2: explain preserved or lowered severity.
				"resource_applicability":                string(resourceApplicability.State), // WO-65@v2: record catalog proof state.
				"resource_applicability_reason":         resourceApplicability.Reason,        // WO-65@v2: explain neutralization decisions.
				"resource_applicability_catalog_digest": resourceApplicabilityCatalogDigest,  // WO-65@v2: bind evidence to its pinned source.
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
