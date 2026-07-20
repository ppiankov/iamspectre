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
func (s *RoleScanner) Scan(ctx context.Context, cfg iam.ScanConfig) (*iam.ScanResult, error) {
	roles, err := s.listRoles(ctx)
	if err != nil {
		return nil, err
	}

	result := &iam.ScanResult{PrincipalsScanned: len(roles)}
	now := time.Now().UTC()
	threshold := iam.StaleThreshold(now, cfg.StaleDays) // WO-24@v2: use the shared calendar cutoff.

	for _, role := range roles {
		roleName := awssdk.ToString(role.RoleName)
		roleARN := awssdk.ToString(role.Arn)

		if iam.IsExcluded(cfg, roleARN, roleName) { // WO-14@v3: use the shared exclusion policy.
			continue
		}

		serviceLinked := isServiceLinkedRole(role)
		includeUnused := !serviceLinked || cfg.IncludeServiceLinkedRoles
		severity, recommendation := unusedRolePresentation(role, serviceLinked)

		// WO-44@v2: suppress only UNUSED_ROLE; independent trust analysis always follows.
		if includeUnused {
			if role.RoleLastUsed != nil && role.RoleLastUsed.LastUsedDate != nil {
				if role.RoleLastUsed.LastUsedDate.Before(threshold) {
					daysSince := int(now.Sub(*role.RoleLastUsed.LastUsedDate).Hours() / 24)
					result.Findings = append(result.Findings, iam.Finding{
						ID:             iam.FindingUnusedRole,
						Severity:       severity,
						ResourceType:   iam.ResourceIAMRole,
						ResourceID:     roleARN,
						ResourceName:   roleName,
						Message:        fmt.Sprintf("Role not assumed in %d days", daysSince),
						Recommendation: recommendation,
						Metadata: map[string]any{
							"last_used":      role.RoleLastUsed.LastUsedDate.Format(time.RFC3339),
							"days_since_use": daysSince,
						},
					})
				}
			} else if role.CreateDate == nil {
				// WO-50: absent age evidence cannot justify a synthetic UNUSED_ROLE finding.
				result.Errors = append(result.Errors, fmt.Sprintf("evaluate unused role %s: creation date is missing", roleName))
			} else if createDate := awssdk.ToTime(role.CreateDate); createDate.Before(threshold) {
				daysSince := int(now.Sub(createDate).Hours() / 24)
				result.Findings = append(result.Findings, iam.Finding{
					ID:             iam.FindingUnusedRole,
					Severity:       severity,
					ResourceType:   iam.ResourceIAMRole,
					ResourceID:     roleARN,
					ResourceName:   roleName,
					Message:        fmt.Sprintf("Role never assumed (created %d days ago)", daysSince),
					Recommendation: recommendation,
					Metadata: map[string]any{
						"created":        createDate.Format(time.RFC3339),
						"days_since_use": daysSince,
						"never_used":     true,
					},
				})
			}
		}

		// Check cross-account trust
		s.checkCrossAccountTrust(role.AssumeRolePolicyDocument, roleARN, roleName, result)
	}

	return result, nil
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
