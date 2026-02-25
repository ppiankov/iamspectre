package gcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/ppiankov/iamspectre/internal/iam"
)

// overprivilegedRoles are GCP roles that grant excessive permissions to service accounts.
var overprivilegedRoles = map[string]bool{
	"roles/owner":  true,
	"roles/editor": true,
}

// BindingScanner detects overprivileged service account IAM bindings.
type BindingScanner struct {
	api     ResourceManagerAPI
	project string
}

// NewBindingScanner creates a scanner for GCP IAM bindings.
func NewBindingScanner(api ResourceManagerAPI, project string) *BindingScanner {
	return &BindingScanner{api: api, project: project}
}

// Type returns the resource type this scanner handles.
func (s *BindingScanner) Type() iam.ResourceType {
	return iam.ResourceIAMBinding
}

// Scan examines project IAM bindings for overprivileged service accounts.
func (s *BindingScanner) Scan(ctx context.Context, cfg iam.ScanConfig) (*iam.ScanResult, error) {
	policy, err := s.api.GetIamPolicy(ctx, s.project)
	if err != nil {
		return nil, fmt.Errorf("get project IAM policy: %w", err)
	}

	result := &iam.ScanResult{}

	saCount := make(map[string]bool)
	for _, binding := range policy.Bindings {
		if !overprivilegedRoles[binding.Role] {
			continue
		}

		for _, member := range binding.Members {
			if !strings.HasPrefix(member, "serviceAccount:") {
				continue
			}

			email := strings.TrimPrefix(member, "serviceAccount:")
			saCount[email] = true

			if isExcluded(cfg, email, email) {
				continue
			}

			result.Findings = append(result.Findings, iam.Finding{
				ID:             iam.FindingOverprivilegedSA,
				Severity:       iam.SeverityCritical,
				ResourceType:   iam.ResourceIAMBinding,
				ResourceID:     fmt.Sprintf("%s/%s/%s", s.project, binding.Role, email),
				ResourceName:   email,
				Message:        fmt.Sprintf("Service account has %s role on project %s", binding.Role, s.project),
				Recommendation: "Replace with a more restrictive role following least-privilege principle",
				Metadata: map[string]any{
					"project": s.project,
					"role":    binding.Role,
					"member":  member,
				},
			})
		}
	}

	result.PrincipalsScanned = len(saCount)
	return result, nil
}
