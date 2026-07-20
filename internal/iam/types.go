package iam

import (
	"context"
	"time"
)

// Severity levels for findings.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// SeverityRank returns the numeric rank of a severity (higher = more severe).
func SeverityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// ResourceType identifies the cloud resource being audited.
type ResourceType string

const (
	ResourceIAMUser           ResourceType = "iam_user"
	ResourceIAMRole           ResourceType = "iam_role"
	ResourceIAMPolicy         ResourceType = "iam_policy"
	ResourceServiceAccount    ResourceType = "service_account"
	ResourceServiceAccountKey ResourceType = "service_account_key"
	ResourceIAMBinding        ResourceType = "iam_binding"

	ResourceAzureUser             ResourceType = "azure_user"
	ResourceAzureGuestUser        ResourceType = "azure_guest_user"
	ResourceAzureAppRegistration  ResourceType = "azure_app_registration"
	ResourceAzureServicePrincipal ResourceType = "azure_service_principal"
	ResourceAzureDirectoryRole    ResourceType = "azure_directory_role"
)

// FindingID identifies the type of issue detected.
type FindingID string

const (
	FindingStaleUser         FindingID = "STALE_USER"
	FindingInactiveIAMUser   FindingID = "INACTIVE_IAM_USER" // WO-55@v4: whole-principal dormancy is a distinct axis from console-credential staleness.
	FindingStaleAccessKey    FindingID = "STALE_ACCESS_KEY"
	FindingNoMFA             FindingID = "NO_MFA"
	FindingUnusedRole        FindingID = "UNUSED_ROLE"
	FindingUnattachedPolicy  FindingID = "UNATTACHED_POLICY"
	FindingWildcardPolicy    FindingID = "WILDCARD_POLICY"
	FindingCrossAccountTrust FindingID = "CROSS_ACCOUNT_TRUST"
	FindingStaleSA           FindingID = "STALE_SA"
	FindingStaleSAKey        FindingID = "STALE_SA_KEY"
	FindingOverprivilegedSA  FindingID = "OVERPRIVILEGED_SA"

	FindingStaleGuestUser    FindingID = "STALE_GUEST_USER"
	FindingLegacyAuth        FindingID = "LEGACY_AUTH"
	FindingStaleApp          FindingID = "STALE_APP"
	FindingExpiredSecret     FindingID = "EXPIRED_SECRET"
	FindingExpiringSecret    FindingID = "EXPIRING_SECRET"
	FindingStaleSP           FindingID = "STALE_SP"
	FindingOverprivilegedApp FindingID = "OVERPRIVILEGED_APP"
	FindingRootAccessKey     FindingID = "ROOT_ACCESS_KEY" // WO-20@v3: reserve the rubric's tier-zero direct-harm exception.
)

// WO-20@v3: assessment types keep evidence claims and severity derivation machine-checkable.
type EvidenceTier uint8

// WO-20@v3: enumerate the evidence ladder used by rubric v1.
const (
	EvidenceTierFact EvidenceTier = iota
	EvidenceTierPolicyShape
	EvidenceTierContextualized
	EvidenceTierAuthorizationLayers
	EvidenceTierSimulated
	EvidenceTierWitnessed
)

type FindingState string // WO-20@v3: distinguish complete conclusions from bounded uncertainty.

// WO-20@v3: constrain assessment state to determinate or bounded uncertainty.
const (
	FindingStateDeterminate   FindingState = "determinate"
	FindingStateIndeterminate FindingState = "indeterminate"
)

type Reachability string // WO-20@v3: separate authorization reachability from evidence strength.

// WO-20@v3: keep reachability independent from evidence tier.
const (
	ReachabilityUnknown   Reachability = "unknown"
	ReachabilityBlocked   Reachability = "blocked"
	ReachabilityReachable Reachability = "reachable"
)

type BlastRadius string // WO-20@v3: version the scope adjustment independently from impact.

// WO-20@v3: enumerate the v1 blast-radius adjustment inputs.
const (
	BlastRadiusLow      BlastRadius = "low"
	BlastRadiusMedium   BlastRadius = "medium"
	BlastRadiusHigh     BlastRadius = "high"
	BlastRadiusCritical BlastRadius = "critical"
)

type LayerStatus string // WO-20@v3: prevent unevaluated authorization layers from appearing complete.

// WO-20@v3: distinguish evaluated layers from unresolved or inapplicable ones.
const (
	LayerEvaluated     LayerStatus = "evaluated"
	LayerNotApplicable LayerStatus = "not_applicable"
	LayerUnresolved    LayerStatus = "unresolved"
)

type AuthorizationLayer string // WO-20@v3: name every layer considered by rubric v1.

// WO-20@v3: enumerate every authorization layer required by rubric v1.
const (
	LayerIdentityPolicy      AuthorizationLayer = "identity_policy"
	LayerResourcePolicy      AuthorizationLayer = "resource_policy"
	LayerPermissionsBoundary AuthorizationLayer = "permissions_boundary"
	LayerSCP                 AuthorizationLayer = "scp"
	LayerRCP                 AuthorizationLayer = "rcp"
	LayerSessionPolicy       AuthorizationLayer = "session_policy"
	LayerExplicitDeny        AuthorizationLayer = "explicit_deny"
	LayerRequestContext      AuthorizationLayer = "request_context"
	LayerServiceEnforcement  AuthorizationLayer = "service_enforcement"
)

type RubricVersion string // WO-20@v3: make future severity changes explicit and compatible.

// WO-20@v3: bind current assessment semantics to the first rubric version.
const RubricVersionV1 RubricVersion = "v1"

// WO-20@v3: Finding carries optional versioned assessment evidence alongside legacy fields.
type Finding struct {
	ID              FindingID                          `json:"id"`
	Severity        Severity                           `json:"severity"`
	ResourceType    ResourceType                       `json:"resource_type"`
	ResourceID      string                             `json:"resource_id"`
	ResourceName    string                             `json:"resource_name,omitempty"`
	Message         string                             `json:"message"`
	Recommendation  string                             `json:"recommendation"`
	Metadata        map[string]any                     `json:"metadata,omitempty"`
	EvidenceTier    *EvidenceTier                      `json:"evidence_tier,omitempty"`    // WO-20@v3: nil preserves the legacy schema path; tier zero remains explicit.
	State           FindingState                       `json:"state,omitempty"`            // WO-20@v3: surface indeterminate assessments without overclaiming.
	Reachability    Reachability                       `json:"reachability,omitempty"`     // WO-20@v3: record unknown, blocked, or reachable independently.
	Impact          Severity                           `json:"impact,omitempty"`           // WO-20@v3: retain pre-cap harm independently from effective severity.
	BlastRadius     BlastRadius                        `json:"blast_radius,omitempty"`     // WO-20@v3: record the v1 scope adjustment input.
	RubricVersion   RubricVersion                      `json:"rubric_version,omitempty"`   // WO-20@v3: bind assessment semantics to rubric v1.
	EvaluatedLayers map[AuthorizationLayer]LayerStatus `json:"evaluated_layers,omitempty"` // WO-20@v3: expose complete authorization-layer coverage.
}

// WO-70@v3: ScanResult keeps actionable findings, diagnostics, and coverage observations distinct.
type ScanResult struct {
	Findings          []Finding                `json:"findings"`
	Errors            []string                 `json:"errors,omitempty"`
	CoverageGaps      []CoverageGapObservation `json:"coverage_gaps,omitempty"` // WO-70@v3: keep missing evidence separate from actionable findings.
	PrincipalsScanned int                      `json:"principals_scanned"`
}

// WO-70@v3: CoverageGapObservation records one unevaluable check without fabricating a finding.
type CoverageGapObservation struct {
	Capability        string     `json:"capability"`
	Cause             string     `json:"cause"`
	Scope             string     `json:"scope"`
	FindingID         FindingID  `json:"finding_id"`
	AffectedCount     int        `json:"affected_count"`
	EvaluableCount    int        `json:"evaluable_count"`
	TotalCount        int        `json:"total_count"`
	OldestEvidence    *time.Time `json:"oldest_evidence,omitempty"`
	ObservationWindow string     `json:"observation_window,omitempty"`
	FeatureStage      string     `json:"feature_stage,omitempty"`
	MaxConsequence    Severity   `json:"max_consequence"`
}

// WO-15: ScanConfig carries the zero-value-safe Azure guest exclusion control.
type ScanConfig struct {
	StaleDays     int
	SeverityMin   Severity
	Exclude       ExcludeConfig
	ExcludeGuests bool
	// WO-44@v2: zero keeps noisy service-linked UNUSED_ROLE findings suppressed by default.
	IncludeServiceLinkedRoles bool
}

// ExcludeConfig holds resource exclusion rules.
type ExcludeConfig struct {
	ResourceIDs map[string]bool
	Principals  map[string]bool
}

// WO-14@v3: keep exclusion policy identical across every provider package.
func IsExcluded(cfg ScanConfig, resourceID, principalName string) bool {
	if cfg.Exclude.ResourceIDs != nil && cfg.Exclude.ResourceIDs[resourceID] {
		return true
	}
	return cfg.Exclude.Principals != nil && cfg.Exclude.Principals[principalName]
}

// Scanner is the interface each resource-type scanner implements.
type Scanner interface {
	Scan(ctx context.Context, cfg ScanConfig) (*ScanResult, error)
	Type() ResourceType
}
