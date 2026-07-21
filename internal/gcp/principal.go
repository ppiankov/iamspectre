package gcp

import "strings"

const serviceAccountPrincipalPrefix = "serviceAccount:" // WO-89: namespace canonical GCP service-account identities.

// WO-89: canonicalize provider identities before cross-scanner cardinality aggregation.
func canonicalServiceAccountPrincipalID(email string) string {
	normalized := strings.ToLower(strings.TrimSpace(email))
	if normalized == "" {
		return ""
	}
	return serviceAccountPrincipalPrefix + normalized
}
