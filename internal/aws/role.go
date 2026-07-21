package aws

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	iamsvc "github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/ppiankov/iamspectre/internal/iam"
)

const (
	serviceLinkedRolePathPrefix  = "/aws-service-role/"
	serviceLinkedRoleNamePrefix  = "AWSServiceRoleFor"
	identityCenterRolePathPrefix = "/aws-reserved/sso.amazonaws.com/"
	identityCenterRoleNamePrefix = "AWSReservedSSO_"
	serviceLinkedRoleGuidance    = "Review the owning AWS service and remove the role through that service if appropriate"
	identityCenterRoleGuidance   = "Review assignments and permission sets in IAM Identity Center instead of deleting this role directly"
	customerManagedRoleGuidance  = "Delete the role if no longer needed"
	roleLastUsedCapability       = "aws_role_last_used"   // WO-104@v3: stable coverage capability identity.
	roleEvidenceUnavailable      = "evidence_unavailable" // WO-104@v3: stable causal identity for missing usage evidence.
	awsAccountScopePrefix        = "aws-account:"         // WO-104@v3: bind gaps to the audited account.
)

// RoleScanner detects unused roles and cross-account trust issues.
type RoleScanner struct {
	client    IAMAPI
	accountID string
}

// NewRoleScanner creates a scanner for IAM roles.
func NewRoleScanner(client IAMAPI, accountID string) *RoleScanner {
	return &RoleScanner{client: client, accountID: accountID}
}

// Type returns the resource type this scanner handles.
func (s *RoleScanner) Type() iam.ResourceType {
	return iam.ResourceIAMRole
}

// Scan examines all IAM roles for unused and cross-account trust issues.
// WO-104@v3: aggregate unavailable usage evidence across eligible roles into one coverage observation.
func (s *RoleScanner) Scan(ctx context.Context, cfg iam.ScanConfig) (*iam.ScanResult, error) {
	roles, err := s.listRoles(ctx)
	if err != nil {
		return nil, err
	}

	result := &iam.ScanResult{PrincipalsScanned: len(roles)}
	now := time.Now().UTC()
	threshold := iam.StaleThreshold(now, cfg.StaleDays) // WO-24@v2: use the shared calendar cutoff.
	usageTotal, usageEvaluable, usageUnavailable := 0, 0, 0

	for _, role := range roles {
		roleName := awssdk.ToString(role.RoleName)
		roleARN := awssdk.ToString(role.Arn)

		if iam.IsExcluded(cfg, roleARN, roleName) { // WO-14@v3: use the shared exclusion policy.
			continue
		}

		serviceLinked := isServiceLinkedRole(role)
		webIdentity := classifyWebIdentityTrust(role.AssumeRolePolicyDocument) // WO-54@v3: annotate determinate trust without changing the finding decision.
		includeUnused := !serviceLinked || cfg.IncludeServiceLinkedRoles
		severity, recommendation := unusedRolePresentation(role, serviceLinked)

		// WO-44@v2: suppress only UNUSED_ROLE; independent trust analysis always follows.
		if includeUnused {
			usageTotal++ // WO-104@v3: count only roles eligible for the UNUSED_ROLE decision.
			if role.RoleLastUsed != nil && role.RoleLastUsed.LastUsedDate != nil {
				usageEvaluable++
				if role.RoleLastUsed.LastUsedDate.Before(threshold) {
					daysSince := int(now.Sub(*role.RoleLastUsed.LastUsedDate).Hours() / 24)
					message := fmt.Sprintf("Role not assumed in %d days", daysSince)
					metadata := map[string]any{
						"last_used":      role.RoleLastUsed.LastUsedDate.Format(time.RFC3339),
						"days_since_use": daysSince,
					}
					if webIdentity {
						metadata["trust_mechanism"] = "web_identity" // WO-54@v3: annotation does not alter severity or guidance.
					}
					result.Findings = append(result.Findings, iam.Finding{
						ID:             iam.FindingUnusedRole,
						Severity:       severity,
						ResourceType:   iam.ResourceIAMRole,
						ResourceID:     roleARN,
						ResourceName:   roleName,
						Message:        message,
						Recommendation: recommendation,
						Metadata:       metadata,
					})
				}
			} else {
				// WO-50: absent age evidence cannot justify a synthetic UNUSED_ROLE finding.
				// WO-54@v3: CreateDate cannot substitute for missing trailing-window usage evidence.
				usageUnavailable++ // WO-104@v3: aggregate known missing evidence outside the error plane.
			}
		}

		// Check cross-account trust
		s.checkCrossAccountTrust(role.AssumeRolePolicyDocument, roleARN, roleName, result)
	}
	if usageUnavailable > 0 {
		// WO-104@v3: emit one account-scoped observation so reporter aggregation cannot flood errors.
		result.CoverageGaps = append(result.CoverageGaps, iam.CoverageGapObservation{
			Capability:     roleLastUsedCapability,
			Cause:          roleEvidenceUnavailable,
			Scope:          awsAccountScopePrefix + s.accountID,
			FindingID:      iam.FindingUnusedRole,
			AffectedCount:  usageUnavailable,
			EvaluableCount: usageEvaluable,
			TotalCount:     usageTotal,
			MaxConsequence: iam.SeverityMedium,
		})
	}

	return result, nil
}

// WO-54@v3: classify only determinate OIDC trust grants for metadata annotation.
func classifyWebIdentityTrust(policyDoc *string) bool {
	if policyDoc == nil {
		return false
	}
	doc, err := ParsePolicyDocument(*policyDoc)
	if err != nil {
		return false
	}
	for _, statement := range doc.Statement {
		if statement.Effect != "Allow" || statement.AssessActions().State != ActionAssessmentDeterminate {
			continue
		}
		grantsWebIdentity := false
		for _, action := range statement.Action {
			if matchesActionPattern(action, "sts:AssumeRoleWithWebIdentity") {
				grantsWebIdentity = true
				break
			}
		}
		if !grantsWebIdentity || statement.Principal == nil {
			continue
		}
		for _, principal := range statement.Principal.Federated {
			parts := strings.SplitN(principal, ":", 6)
			if len(parts) == 6 && parts[0] == "arn" && strings.EqualFold(parts[2], "iam") &&
				strings.HasPrefix(parts[5], "oidc-provider/") {
				return true
			}
		}
	}
	return false
}

// WO-44@v2: recognize only structural service-linked path, ARN, or canonical name shapes.
func isServiceLinkedRole(role iamtypes.Role) bool {
	return strings.HasPrefix(awssdk.ToString(role.Path), serviceLinkedRolePathPrefix) ||
		strings.Contains(awssdk.ToString(role.Arn), ":role/aws-service-role/") ||
		strings.HasPrefix(awssdk.ToString(role.RoleName), serviceLinkedRoleNamePrefix)
}

// WO-51: require both canonical Identity Center path and reserved role name.
func isIdentityCenterRole(role iamtypes.Role) bool {
	return strings.HasPrefix(awssdk.ToString(role.Path), identityCenterRolePathPrefix) &&
		strings.HasPrefix(awssdk.ToString(role.RoleName), identityCenterRoleNamePrefix)
}

// WO-49: centralize the safe remediation boundary for AWS-owned role families.
// WO-44@v2: AWS-owned roles need restrained severity and lifecycle-specific guidance.
func unusedRolePresentation(role iamtypes.Role, serviceLinked bool) (iam.Severity, string) {
	if serviceLinked {
		return iam.SeverityLow, serviceLinkedRoleGuidance
	}
	if isIdentityCenterRole(role) {
		return iam.SeverityLow, identityCenterRoleGuidance
	}
	return iam.SeverityMedium, customerManagedRoleGuidance
}

func (s *RoleScanner) checkCrossAccountTrust(policyDoc *string, roleARN, roleName string, result *iam.ScanResult) {
	if policyDoc == nil {
		return
	}

	doc, err := ParsePolicyDocument(*policyDoc)
	if err != nil {
		slog.Warn("Failed to parse trust policy", "role", roleName, "error", err)
		result.Errors = append(result.Errors, fmt.Sprintf("parse trust policy %s: %v", roleName, err)) // WO-46: preserve lost coverage in reports.
		return
	}

	for _, stmt := range doc.Statement {
		if stmt.Effect != "Allow" {
			continue
		}
		if !stmt.HasAssumeRoleAction() { // WO-40: unrelated trust-policy actions cannot grant role assumption.
			continue
		}
		if stmt.Principal == nil {
			continue
		}

		principals := stmt.Principal.AWS
		if stmt.Principal.Wildcard {
			principals = append(principals, "*") // WO-37@v2: evaluate literal wildcard trust through the same condition gate.
		}

		for _, principal := range principals {
			if !s.isExternalAccount(principal) {
				continue
			}
			if stmt.HasRestrictiveTrustCondition() { // WO-19@v3: unknown or broad conditions must fail open.
				continue
			}

			result.Findings = append(result.Findings, iam.Finding{
				ID:             iam.FindingCrossAccountTrust,
				Severity:       iam.SeverityCritical,
				ResourceType:   iam.ResourceIAMRole,
				ResourceID:     roleARN,
				ResourceName:   roleName,
				Message:        fmt.Sprintf("External account trust without conditions: %s", principal),
				Recommendation: "Add conditions (e.g., ExternalId) to the trust policy or remove if unnecessary",
				Metadata: map[string]any{
					"trusted_principal": principal,
				},
			})
		}
	}
}

// isExternalAccount checks if a principal ARN belongs to a different AWS account.
func (s *RoleScanner) isExternalAccount(principal string) bool {
	if principal == "*" {
		return true
	}

	// Extract account ID from ARN: arn:aws:iam::ACCOUNT_ID:...
	if !strings.HasPrefix(principal, "arn:aws:iam::") {
		return false
	}
	parts := strings.SplitN(principal, ":", 6)
	if len(parts) < 5 {
		return false
	}
	return parts[4] != s.accountID
}

func (s *RoleScanner) listRoles(ctx context.Context) ([]iamtypes.Role, error) {
	var roles []iamtypes.Role
	var marker *string

	for {
		out, err := s.client.ListRoles(ctx, &iamsvc.ListRolesInput{
			Marker:   marker,
			MaxItems: awssdk.Int32(100),
		})
		if err != nil {
			return nil, fmt.Errorf("list IAM roles: %w", err)
		}

		roles = append(roles, out.Roles...)

		if !out.IsTruncated {
			break
		}
		marker = out.Marker
	}

	slog.Debug("Listed IAM roles", "count", len(roles))
	return roles, nil
}
