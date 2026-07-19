package iam

// WO-20@v3: canonical authorization layers make incomplete assessments fail closed.
var canonicalAuthorizationLayers = [...]AuthorizationLayer{
	LayerIdentityPolicy,
	LayerResourcePolicy,
	LayerPermissionsBoundary,
	LayerSCP,
	LayerRCP,
	LayerSessionPolicy,
	LayerExplicitDeny,
	LayerRequestContext,
	LayerServiceEnforcement,
}

// WO-20@v3: CanonicalLayers returns the immutable v1 layer order as a caller-owned slice.
func CanonicalLayers() []AuthorizationLayer {
	return append([]AuthorizationLayer(nil), canonicalAuthorizationLayers[:]...)
}

// WO-20@v3: HasAssessment distinguishes explicit rubric input from metadata-free legacy findings.
func HasAssessment(f Finding) bool {
	return hasAssessment(f)
}

// WO-20@v3: EffectiveSeverity applies the versioned restraint-first severity rubric.
func EffectiveSeverity(f Finding) Severity {
	if !hasAssessment(f) {
		return f.Severity
	}
	if !validAssessment(f) {
		return capSeverity(f.Severity, SeverityMedium)
	}

	effective := adjustForBlastRadius(f.Impact, f.BlastRadius)
	effective = capSeverity(effective, evidenceCap(f))

	directHarm := (f.ID == FindingRootAccessKey && *f.EvidenceTier == EvidenceTierFact) ||
		*f.EvidenceTier == EvidenceTierWitnessed
	if !directHarm && (f.Reachability == ReachabilityUnknown || hasUnresolvedLayer(f)) {
		effective = capSeverity(effective, SeverityMedium)
	}
	if f.Reachability == ReachabilityBlocked {
		effective = capSeverity(effective, SeverityLow)
	}
	return effective
}

// WO-20@v3: NormalizeSeverity returns a copy so analyzer normalization never mutates scanner output.
func NormalizeSeverity(f Finding) Finding {
	effective := EffectiveSeverity(f)
	if hasAssessment(f) && !validAssessment(f) {
		f.State = FindingStateIndeterminate
	}
	f.Severity = effective
	return f
}

// WO-20@v3: distinguish explicit tier-zero assessments from metadata-free legacy findings.
func hasAssessment(f Finding) bool {
	return f.RubricVersion != "" || f.State != "" || f.Reachability != "" || f.Impact != "" ||
		f.BlastRadius != "" || f.EvidenceTier != nil || f.EvaluatedLayers != nil
}

// WO-20@v3: reject incomplete rubric inputs instead of deriving overconfident severity.
func validAssessment(f Finding) bool {
	if f.RubricVersion != RubricVersionV1 || f.EvidenceTier == nil || *f.EvidenceTier > EvidenceTierWitnessed {
		return false
	}
	if f.State != FindingStateDeterminate && f.State != FindingStateIndeterminate {
		return false
	}
	if f.Reachability != ReachabilityUnknown && f.Reachability != ReachabilityBlocked && f.Reachability != ReachabilityReachable {
		return false
	}
	if SeverityRank(f.Impact) == 0 || !validBlastRadius(f.BlastRadius) {
		return false
	}
	if len(f.EvaluatedLayers) != len(canonicalAuthorizationLayers) {
		return false
	}
	for _, layer := range canonicalAuthorizationLayers {
		status, ok := f.EvaluatedLayers[layer]
		if !ok || (status != LayerEvaluated && status != LayerNotApplicable && status != LayerUnresolved) {
			return false
		}
	}
	return true
}

// WO-20@v3: constrain blast-radius inputs to the versioned vocabulary.
func validBlastRadius(radius BlastRadius) bool {
	return radius == BlastRadiusLow || radius == BlastRadiusMedium || radius == BlastRadiusHigh || radius == BlastRadiusCritical
}

// WO-20@v3: apply the rubric's bounded scope adjustment before confidence caps.
func adjustForBlastRadius(impact Severity, radius BlastRadius) Severity {
	rank := SeverityRank(impact)
	switch radius {
	case BlastRadiusLow:
		rank--
	case BlastRadiusHigh:
		rank++
	case BlastRadiusCritical:
		rank += 2
	}
	return severityAtRank(rank)
}

// WO-20@v3: cap severity at the strongest claim supported by the evidence tier.
func evidenceCap(f Finding) Severity {
	if f.ID == FindingRootAccessKey && *f.EvidenceTier == EvidenceTierFact {
		return SeverityCritical
	}
	if *f.EvidenceTier >= EvidenceTierSimulated ||
		(*f.EvidenceTier == EvidenceTierAuthorizationLayers && f.Reachability == ReachabilityReachable) {
		return SeverityCritical
	}
	return SeverityHigh
}

// WO-20@v3: unresolved applicable layers force the restraint cap.
func hasUnresolvedLayer(f Finding) bool {
	for _, status := range f.EvaluatedLayers {
		if status == LayerUnresolved {
			return true
		}
	}
	return false
}

// WO-20@v3: ensure confidence caps always win over impact adjustments.
func capSeverity(severity, cap Severity) Severity {
	if SeverityRank(severity) > SeverityRank(cap) {
		return cap
	}
	return severity
}

// WO-20@v3: clamp arithmetic results to the four canonical severity ranks.
func severityAtRank(rank int) Severity {
	switch {
	case rank <= SeverityRank(SeverityLow):
		return SeverityLow
	case rank == SeverityRank(SeverityMedium):
		return SeverityMedium
	case rank == SeverityRank(SeverityHigh):
		return SeverityHigh
	default:
		return SeverityCritical
	}
}
