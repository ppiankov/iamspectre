package iam

import "context"

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
)

// FindingID identifies the type of issue detected.
type FindingID string

const (
	FindingStaleUser         FindingID = "STALE_USER"
	FindingStaleAccessKey    FindingID = "STALE_ACCESS_KEY"
	FindingNoMFA             FindingID = "NO_MFA"
	FindingUnusedRole        FindingID = "UNUSED_ROLE"
	FindingUnattachedPolicy  FindingID = "UNATTACHED_POLICY"
	FindingWildcardPolicy    FindingID = "WILDCARD_POLICY"
	FindingCrossAccountTrust FindingID = "CROSS_ACCOUNT_TRUST"
	FindingStaleSA           FindingID = "STALE_SA"
	FindingStaleSAKey        FindingID = "STALE_SA_KEY"
	FindingOverprivilegedSA  FindingID = "OVERPRIVILEGED_SA"
)

// Finding represents a single IAM audit finding.
type Finding struct {
	ID             FindingID      `json:"id"`
	Severity       Severity       `json:"severity"`
	ResourceType   ResourceType   `json:"resource_type"`
	ResourceID     string         `json:"resource_id"`
	ResourceName   string         `json:"resource_name,omitempty"`
	Message        string         `json:"message"`
	Recommendation string         `json:"recommendation"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

// ScanResult holds all findings from scanning IAM resources.
type ScanResult struct {
	Findings          []Finding `json:"findings"`
	Errors            []string  `json:"errors,omitempty"`
	PrincipalsScanned int       `json:"principals_scanned"`
}

// ScanConfig holds parameters that control scanning behavior.
type ScanConfig struct {
	StaleDays   int
	SeverityMin Severity
	Exclude     ExcludeConfig
}

// ExcludeConfig holds resource exclusion rules.
type ExcludeConfig struct {
	ResourceIDs map[string]bool
	Principals  map[string]bool
}

// Scanner is the interface each resource-type scanner implements.
type Scanner interface {
	Scan(ctx context.Context, cfg ScanConfig) (*ScanResult, error)
	Type() ResourceType
}
