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

const (
	googleAPIsServiceAgentDomain = "@cloudservices.gserviceaccount.com"
	defaultComputeAccountSuffix  = "-compute@developer.gserviceaccount.com"
)

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

	// WO-89@v4: a successful policy read makes even an empty observed identity set complete.
	result := &iam.ScanResult{
		ObservedPrincipalIDs:                make(map[string]struct{}),
		PrincipalIdentityAccountingComplete: true,
	}
	// WO-83@v5: project-number lookup is independent evidence; failure must preserve candidates.
	project, projectErr := s.api.GetProject(ctx, s.project)
	if projectErr == nil && (project == nil || project.ProjectNumber <= 0) {
		projectErr = fmt.Errorf("project metadata missing project number")
	}
	localGoogleAPIsAgent := ""
	localDefaultCompute := ""
	if projectErr == nil {
		projectNumber := fmt.Sprintf("%d", project.ProjectNumber)
		localGoogleAPIsAgent = projectNumber + googleAPIsServiceAgentDomain
		localDefaultCompute = projectNumber + defaultComputeAccountSuffix
	}
	classificationCandidates := 0
	legacyPrincipalIDs := make(map[string]struct{}) // WO-89@v4: preserve additive fallback when an observed member has no usable identity.
	for _, binding := range policy.Bindings {
		for _, member := range binding.Members {
			if !strings.HasPrefix(member, serviceAccountPrincipalPrefix) {
				continue
			}

			email := strings.TrimPrefix(member, serviceAccountPrincipalPrefix)
			normalizedEmail := strings.ToLower(strings.TrimSpace(email))
			legacyPrincipalIDs[email] = struct{}{}
			principalID := canonicalServiceAccountPrincipalID(email)
			if principalID == "" {
				result.PrincipalIdentityAccountingComplete = false // WO-89@v4: never count a synthetic namespace-only identity.
			} else {
				result.ObservedPrincipalIDs[principalID] = struct{}{} // WO-89@v4: count every observed service account independently of finding selection.
			}
			if !overprivilegedRoles[binding.Role] {
				continue
			}

			if iam.IsExcluded(cfg, email, email) { // WO-14@v3: use the shared exclusion policy.
				continue
			}
			if binding.Role == "roles/editor" && strings.HasSuffix(normalizedEmail, googleAPIsServiceAgentDomain) {
				// WO-83@v5: only cloudservices Editor bindings depend on local project-number correlation.
				classificationCandidates++
			}
			// WO-83@v5: suppress only the exact local provider-owned Editor grant.
			if binding.Role == "roles/editor" && projectErr == nil && normalizedEmail == localGoogleAPIsAgent {
				continue
			}

			recommendation := "Replace with a more restrictive role following least-privilege principle"
			if binding.Role == "roles/editor" && projectErr == nil && normalizedEmail == localDefaultCompute {
				// WO-83@v5: default Compute accounts are customer-managed; preserve the finding with safe advice.
				recommendation = "Use Policy Simulator or IAM role recommendations before replacing the Editor role"
			}

			result.Findings = append(result.Findings, iam.Finding{
				ID:             iam.FindingOverprivilegedSA,
				Severity:       iam.SeverityCritical,
				ResourceType:   iam.ResourceIAMBinding,
				ResourceID:     fmt.Sprintf("%s/%s/%s", s.project, binding.Role, email),
				ResourceName:   email,
				Message:        fmt.Sprintf("Service account has %s role on project %s", binding.Role, s.project),
				Recommendation: recommendation,
				Metadata: map[string]any{
					"project": s.project,
					"role":    binding.Role,
					"member":  member,
				},
			})
		}
	}
	if projectErr != nil && classificationCandidates > 0 {
		// WO-83@v5: fail closed while making the managed-grant classification gap explicit.
		result.Errors = append(result.Errors, fmt.Sprintf("classify managed service agents: %v", projectErr))
		result.CoverageGaps = append(result.CoverageGaps, iam.CoverageGapObservation{
			Capability: "gcp_managed_service_agent_classification", Cause: "project_metadata_unavailable",
			Scope: "gcp-project:" + s.project, FindingID: iam.FindingOverprivilegedSA,
			AffectedCount: classificationCandidates, TotalCount: classificationCandidates,
			FeatureStage: "v1", MaxConsequence: iam.SeverityCritical,
		})
	}

	if result.PrincipalIdentityAccountingComplete {
		result.PrincipalsScanned = len(result.ObservedPrincipalIDs)
	} else {
		result.PrincipalsScanned = len(legacyPrincipalIDs)
	}
	return result, nil
}
