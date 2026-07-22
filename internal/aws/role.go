package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
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
	roleLastUsedCapability       = "aws_role_last_used"     // WO-104@v3: stable coverage capability identity.
	roleEvidenceUnavailable      = "evidence_unavailable"   // WO-104@v3: stable causal identity for missing usage evidence.
	roleGetRoleDenied            = "getrole_denied"         // WO-110@v5: distinguish authorization gaps without retaining provider errors.
	roleGetRoleThrottled         = "getrole_throttled"      // WO-110@v5: expose retryable provider coverage loss.
	roleGetRoleFailed            = "getrole_failed"         // WO-110@v5: bound every other non-context failure to a stable cause.
	awsAccountScopePrefix        = "aws-account:"           // WO-104@v3: bind gaps to the audited account.
	podIdentityServicePrincipal  = "pods.eks.amazonaws.com" // WO-109@v2: canonical EKS Pod Identity trust principal.
)

// RoleScanner detects unused roles and cross-account trust issues.
type RoleScanner struct {
	client    IAMAPI
	accountID string
	now       func() time.Time // WO-124: inject one scan instant for deterministic thresholds and evidence provenance.
}

// NewRoleScanner creates a scanner for IAM roles.
// WO-124: install the production clock while retaining a deterministic package-local test seam.
func NewRoleScanner(client IAMAPI, accountID string) *RoleScanner {
	return &RoleScanner{client: client, accountID: accountID, now: time.Now}
}

// Type returns the resource type this scanner handles.
func (s *RoleScanner) Type() iam.ResourceType {
	return iam.ResourceIAMRole
}

// Scan examines all IAM roles for unused and cross-account trust issues.
// WO-104@v3: aggregate unavailable usage evidence across eligible roles into one coverage observation.
// WO-107@v2: enrich only eligible roles whose list record lacks usable RoleLastUsed evidence.
func (s *RoleScanner) Scan(ctx context.Context, cfg iam.ScanConfig) (*iam.ScanResult, error) {
	roles, err := s.listRoles(ctx)
	if err != nil {
		return nil, err
	}

	result := &iam.ScanResult{PrincipalsScanned: len(roles)}
	nowFn := s.now
	if nowFn == nil {
		nowFn = time.Now // WO-124: preserve zero-value safety for package-local scanner construction.
	}
	now := nowFn().UTC()
	threshold := iam.StaleThreshold(now, cfg.StaleDays) // WO-24@v2: use the shared calendar cutoff.
	usageTotal, usageEvaluable, usageUnavailable := 0, 0, 0

	for _, role := range roles {
		roleName := awssdk.ToString(role.RoleName)
		roleARN := awssdk.ToString(role.Arn)

		if iam.IsExcluded(cfg, roleARN, roleName) { // WO-14@v3: use the shared exclusion policy.
			continue
		}

		serviceLinked := isServiceLinkedRole(role)
		webIdentityObservations := observeWebIdentityTrust(role.AssumeRolePolicyDocument)
		webIdentity := len(webIdentityObservations) > 0                        // WO-54@v3: annotate determinate trust without changing the finding decision.
		podIdentity := classifyPodIdentityTrust(role.AssumeRolePolicyDocument) // WO-109@v2: preserve the structurally distinct Pod Identity mechanism.
		includeUnused := !serviceLinked || cfg.IncludeServiceLinkedRoles
		severity, recommendation := unusedRolePresentation(role, serviceLinked)

		// WO-119@v2: trust observations are positive IAM facts independent of the UNUSED_ROLE decision.
		for _, observation := range webIdentityObservations {
			edge := iam.NewIAMTrustWebIdentityObservedEdge(
				roleARN, roleName, observation.issuer, observation.subjectConditions, now,
			)
			if edge != nil { // WO-119@v2: malformed provider identity cannot become positive evidence.
				result.IAMPositiveEdges = append(result.IAMPositiveEdges, edge)
			}
		}
		if podIdentity {
			edge := iam.NewIAMTrustPodIdentityObservedEdge(roleARN, roleName, now)
			if edge != nil { // WO-119@v2: malformed provider identity cannot become positive evidence.
				result.IAMPositiveEdges = append(result.IAMPositiveEdges, edge)
			}
		}

		roleLastUsed := role.RoleLastUsed

		// WO-44@v2: suppress only UNUSED_ROLE; independent trust analysis always follows.
		if includeUnused {
			usageTotal++ // WO-104@v3: count only roles eligible for the UNUSED_ROLE decision.
			resolvedRoleLastUsed, unavailableCause, err := s.resolveRoleLastUsed(ctx, role)
			if err != nil {
				return nil, err
			}
			roleLastUsed = resolvedRoleLastUsed
			if roleLastUsed != nil && roleLastUsed.LastUsedDate != nil {
				usageEvaluable++
				if roleLastUsed.LastUsedDate.Before(threshold) {
					daysSince := int(now.Sub(*roleLastUsed.LastUsedDate).Hours() / 24)
					message := fmt.Sprintf("Role not assumed in %d days", daysSince)
					metadata := map[string]any{
						"last_used":      roleLastUsed.LastUsedDate.Format(time.RFC3339),
						"days_since_use": daysSince,
					}
					if podIdentity {
						metadata["trust_mechanism"] = "pod_identity" // WO-109@v2: singular metadata uses deterministic Pod Identity precedence.
					} else if webIdentity {
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
				// WO-110@v5: retain bounded role-level cause and identity only for opt-in/in-process use.
				usageUnavailable++ // WO-104@v3: preserve the single bounded aggregate and its denominator.
				result.CoverageGapDetails = append(result.CoverageGapDetails, iam.CoverageGapDetail{
					Capability:   roleLastUsedCapability,
					Cause:        unavailableCause,
					ResourceType: iam.ResourceIAMRole,
					ResourceID:   roleARN,
					ResourceName: roleName,
				})
				slog.Debug("role_last_used_coverage_detail", "role", roleName, "cause", unavailableCause)
			}
		}
		if roleLastUsed != nil && roleLastUsed.LastUsedDate != nil {
			lastUsedAt := roleLastUsed.LastUsedDate.UTC()
			// WO-119@v2: populated usage is an observed fact even when no stale finding exists.
			edge := iam.NewRoleActivityObservedEdge(
				roleARN, roleName, lastUsedAt, awssdk.ToString(roleLastUsed.Region), now,
			)
			if edge != nil { // WO-119@v2: malformed provider identity cannot become positive evidence.
				result.IAMPositiveEdges = append(result.IAMPositiveEdges, edge)
			}
		}

		// Check cross-account trust
		s.checkCrossAccountTrust(role.AssumeRolePolicyDocument, roleARN, roleName, result)
	}
	if usageUnavailable > 0 {
		// WO-104@v3: emit one account-scoped observation so reporter aggregation cannot flood errors.
		// WO-110@v5: specific causes stay in private detail so the aggregate denominator cannot be counted twice.
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
	// WO-119@v2: canonicalize private edge order independently of provider pagination and policy maps.
	sort.SliceStable(result.IAMPositiveEdges, func(i, j int) bool {
		return iamPositiveEdgeSortKey(result.IAMPositiveEdges[i]) < iamPositiveEdgeSortKey(result.IAMPositiveEdges[j])
	})

	return result, nil
}

// WO-107@v2: ListRoles omits usage evidence, so recover only that field through one bounded request.
// WO-110@v5: return a stable private cause for every non-fatal unresolved enrichment.
func (s *RoleScanner) resolveRoleLastUsed(ctx context.Context, role iamtypes.Role) (*iamtypes.RoleLastUsed, string, error) {
	if role.RoleLastUsed != nil && role.RoleLastUsed.LastUsedDate != nil {
		return role.RoleLastUsed, "", nil
	}
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	roleName := awssdk.ToString(role.RoleName)
	if roleName == "" {
		return nil, roleEvidenceUnavailable, nil
	}

	out, err := s.client.GetRole(ctx, &iamsvc.GetRoleInput{RoleName: awssdk.String(roleName)})
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, "", ctxErr
		}
		return nil, classifyGetRoleFailure(err), nil
	}
	if out == nil || out.Role == nil {
		return nil, roleEvidenceUnavailable, nil
	}
	if out.Role.RoleLastUsed == nil || out.Role.RoleLastUsed.LastUsedDate == nil {
		return nil, roleEvidenceUnavailable, nil
	}
	return out.Role.RoleLastUsed, "", nil
}

// WO-110@v5: awsAPIErrorCoder exposes only the stable provider code needed for safe classification.
type awsAPIErrorCoder interface {
	ErrorCode() string
}

// WO-110@v5: classify only stable provider codes; raw messages stay outside customer output.
func classifyGetRoleFailure(err error) string {
	var apiErr awsAPIErrorCoder
	if !errors.As(err, &apiErr) {
		return roleGetRoleFailed
	}
	switch strings.ToLower(apiErr.ErrorCode()) {
	case "accessdenied", "accessdeniedexception", "unauthorizedaccess", "unauthorizedoperation":
		return roleGetRoleDenied
	case "throttling", "throttlingexception", "toomanyrequestsexception", "requestlimitexceeded":
		return roleGetRoleThrottled
	default:
		return roleGetRoleFailed
	}
}

// WO-119@v2: webIdentityTrustObservation carries lossless evidence between parsing and validation.
type webIdentityTrustObservation struct {
	issuer            string                         // WO-119@v2: preserve the provider resource verbatim.
	subjectConditions []iam.IAMTrustSubjectCondition // WO-119@v2: retain only issuer-scoped subject constraints.
}

// WO-119@v2: rawTrustStatement aligns raw condition values with normalized statements by index.
type rawTrustStatement struct {
	Condition json.RawMessage `json:"Condition"` // WO-119@v2: defer condition interpretation until the issuer is known.
}

// WO-119@v2: extract every determinate OIDC grant without resolving the raw issuer or subject grammar.
func observeWebIdentityTrust(policyDoc *string) []webIdentityTrustObservation {
	if policyDoc == nil {
		return nil
	}
	doc, err := ParsePolicyDocument(*policyDoc)
	if err != nil {
		return nil
	}
	rawStatements := parseRawTrustStatements(*policyDoc)
	observations := make([]webIdentityTrustObservation, 0)
	for statementIndex, statement := range doc.Statement {
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
			issuer, ok := oidcIssuerFromPrincipal(principal)
			if !ok {
				continue
			}
			var conditions []iam.IAMTrustSubjectCondition
			if statementIndex < len(rawStatements) {
				conditions = rawSubjectConditions(rawStatements[statementIndex].Condition, issuer)
			}
			observations = append(observations, webIdentityTrustObservation{issuer: issuer, subjectConditions: conditions})
		}
	}
	sort.SliceStable(observations, func(i, j int) bool {
		return webIdentityObservationKey(observations[i]) < webIdentityObservationKey(observations[j])
	})
	return observations
}

// WO-54@v3: retain the legacy boolean seam over the lossless positive observation extractor.
func classifyWebIdentityTrust(policyDoc *string) bool {
	return len(observeWebIdentityTrust(policyDoc)) > 0
}

// WO-119@v2: retain the provider resource verbatim after structural IAM OIDC ARN validation.
func oidcIssuerFromPrincipal(principal string) (string, bool) {
	parts := strings.SplitN(principal, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || !strings.EqualFold(parts[2], "iam") ||
		!strings.HasPrefix(parts[5], "oidc-provider/") {
		return "", false
	}
	issuer := strings.TrimPrefix(parts[5], "oidc-provider/")
	return issuer, issuer != ""
}

// WO-119@v2: align raw statement conditions with the normalized policy statements without interpreting values.
func parseRawTrustStatements(policyDoc string) []rawTrustStatement {
	decoded, err := url.QueryUnescape(policyDoc)
	if err != nil {
		return nil
	}
	var envelope struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(decoded), &envelope); err != nil {
		return nil
	}
	statementJSON := strings.TrimSpace(string(envelope.Statement))
	if statementJSON == "" {
		return nil
	}
	if strings.HasPrefix(statementJSON, "[") {
		var statements []rawTrustStatement
		if err := json.Unmarshal(envelope.Statement, &statements); err != nil {
			return nil
		}
		return statements
	}
	var statement rawTrustStatement
	if err := json.Unmarshal(envelope.Statement, &statement); err != nil {
		return nil
	}
	return []rawTrustStatement{statement}
}

// WO-119@v2: preserve only issuer-specific subject constraints as raw JSON values.
func rawSubjectConditions(raw json.RawMessage, issuer string) []iam.IAMTrustSubjectCondition {
	var operators map[string]map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &operators) != nil {
		return nil
	}
	wantedKey := issuer + ":sub"
	conditions := make([]iam.IAMTrustSubjectCondition, 0)
	for operator, entries := range operators {
		for key, value := range entries {
			if key != wantedKey {
				continue
			}
			conditions = append(conditions, iam.IAMTrustSubjectCondition{
				Operator: operator,
				Key:      key,
				RawValue: string(value),
			})
		}
	}
	sort.SliceStable(conditions, func(i, j int) bool {
		left, right := conditions[i], conditions[j]
		return left.Operator+"\x00"+left.Key+"\x00"+left.RawValue < right.Operator+"\x00"+right.Key+"\x00"+right.RawValue
	})
	return conditions
}

// WO-119@v2: produce a deterministic key without adding a public serialization contract.
func webIdentityObservationKey(observation webIdentityTrustObservation) string {
	parts := []string{observation.issuer}
	for _, condition := range observation.subjectConditions {
		parts = append(parts, condition.Operator, condition.Key, condition.RawValue)
	}
	return strings.Join(parts, "\x00")
}

// WO-119@v2: sort sealed edge variants by role, positive kind, and raw evidence.
func iamPositiveEdgeSortKey(edge iam.IAMPositiveEdge) string {
	switch edge.Type() {
	case iam.IAMTrustWebIdentityObserved:
		issuer, conditions, ok := iam.IAMTrustWebIdentityEvidence(edge)
		if !ok {
			return "\xff"
		}
		return edge.RoleARN() + "\x00" + "1" + "\x00" + webIdentityObservationKey(webIdentityTrustObservation{
			issuer: issuer, subjectConditions: conditions,
		})
	case iam.IAMTrustPodIdentityObserved:
		return edge.RoleARN() + "\x00" + "2"
	case iam.RoleActivityObserved:
		return edge.RoleARN() + "\x00" + "3"
	default:
		return "\xff"
	}
}

// WO-109@v2: classify only complete, determinate EKS Pod Identity trust grants.
func classifyPodIdentityTrust(policyDoc *string) bool {
	if policyDoc == nil {
		return false
	}
	doc, err := ParsePolicyDocument(*policyDoc)
	if err != nil {
		return false
	}
	grantsAssumeRole, grantsTagSession := false, false
	for _, statement := range doc.Statement {
		if statement.Effect != "Allow" || statement.Principal == nil ||
			statement.AssessActions().State != ActionAssessmentDeterminate {
			continue
		}
		podIdentityPrincipal := false
		for _, principal := range statement.Principal.Service {
			if strings.EqualFold(principal, podIdentityServicePrincipal) {
				podIdentityPrincipal = true
				break
			}
		}
		if !podIdentityPrincipal {
			continue
		}
		for _, action := range statement.Action {
			grantsAssumeRole = grantsAssumeRole || matchesActionPattern(action, "sts:AssumeRole")
			grantsTagSession = grantsTagSession || matchesActionPattern(action, "sts:TagSession")
		}
	}
	return grantsAssumeRole && grantsTagSession
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

	parts := strings.SplitN(principal, ":", 6)
	// WO-125: IAM is global inside each AWS partition, so validate components without hardcoding arn:aws.
	if len(parts) != 6 || parts[0] != "arn" || parts[1] == "" || !strings.EqualFold(parts[2], "iam") ||
		parts[3] != "" || !isAWSAccountID(parts[4]) || parts[5] == "" {
		return false
	}
	return parts[4] != s.accountID
}

// WO-125: accept only the fixed-width decimal account identifier used by IAM ARNs.
func isAWSAccountID(value string) bool {
	if len(value) != 12 {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
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
