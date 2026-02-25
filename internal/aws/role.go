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

// serviceLinkedRolePathPrefix identifies AWS service-linked roles that should be skipped.
const serviceLinkedRolePathPrefix = "/aws-service-role/"

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
	threshold := now.AddDate(0, 0, -cfg.StaleDays)

	for _, role := range roles {
		roleName := awssdk.ToString(role.RoleName)
		roleARN := awssdk.ToString(role.Arn)

		if isExcluded(cfg, roleARN, roleName) {
			continue
		}

		// Skip service-linked roles
		if strings.HasPrefix(awssdk.ToString(role.Path), serviceLinkedRolePathPrefix) {
			continue
		}

		// Check if role is unused
		if role.RoleLastUsed != nil && role.RoleLastUsed.LastUsedDate != nil {
			if role.RoleLastUsed.LastUsedDate.Before(threshold) {
				daysSince := int(now.Sub(*role.RoleLastUsed.LastUsedDate).Hours() / 24)
				result.Findings = append(result.Findings, iam.Finding{
					ID:             iam.FindingUnusedRole,
					Severity:       iam.SeverityMedium,
					ResourceType:   iam.ResourceIAMRole,
					ResourceID:     roleARN,
					ResourceName:   roleName,
					Message:        fmt.Sprintf("Role not assumed in %d days", daysSince),
					Recommendation: "Delete the role if no longer needed",
					Metadata: map[string]any{
						"last_used":      role.RoleLastUsed.LastUsedDate.Format(time.RFC3339),
						"days_since_use": daysSince,
					},
				})
			}
		} else {
			// Role has never been used — check if old enough to flag
			createDate := awssdk.ToTime(role.CreateDate)
			if createDate.Before(threshold) {
				daysSince := int(now.Sub(createDate).Hours() / 24)
				result.Findings = append(result.Findings, iam.Finding{
					ID:             iam.FindingUnusedRole,
					Severity:       iam.SeverityMedium,
					ResourceType:   iam.ResourceIAMRole,
					ResourceID:     roleARN,
					ResourceName:   roleName,
					Message:        fmt.Sprintf("Role never assumed (created %d days ago)", daysSince),
					Recommendation: "Delete the role if no longer needed",
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

func (s *RoleScanner) checkCrossAccountTrust(policyDoc *string, roleARN, roleName string, result *iam.ScanResult) {
	if policyDoc == nil {
		return
	}

	doc, err := ParsePolicyDocument(*policyDoc)
	if err != nil {
		slog.Warn("Failed to parse trust policy", "role", roleName, "error", err)
		return
	}

	for _, stmt := range doc.Statement {
		if stmt.Effect != "Allow" {
			continue
		}
		if stmt.Principal == nil {
			continue
		}

		for _, principal := range stmt.Principal.AWS {
			if !s.isExternalAccount(principal) {
				continue
			}
			if stmt.Condition != nil {
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
