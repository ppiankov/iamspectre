package iam

import "testing"

// WO-20@v3: completeLayers makes every rubric test explicit about authorization coverage.
func completeLayers(status LayerStatus) map[AuthorizationLayer]LayerStatus {
	layers := make(map[AuthorizationLayer]LayerStatus, len(CanonicalLayers()))
	for _, layer := range CanonicalLayers() {
		layers[layer] = status
	}
	return layers
}

// WO-20@v3: preserve explicit tier zero in table fixtures.
func evidenceTier(tier EvidenceTier) *EvidenceTier {
	return &tier
}

// WO-20@v3: provide a complete valid assessment for isolated rubric mutations.
func assessedFinding() Finding {
	return Finding{
		ID:              FindingNoMFA,
		Severity:        SeverityCritical,
		EvidenceTier:    evidenceTier(EvidenceTierAuthorizationLayers),
		State:           FindingStateDeterminate,
		Reachability:    ReachabilityReachable,
		Impact:          SeverityMedium,
		BlastRadius:     BlastRadiusMedium,
		RubricVersion:   RubricVersionV1,
		EvaluatedLayers: completeLayers(LayerEvaluated),
	}
}

// WO-20@v3: pin every blast-radius adjustment and clamp.
func TestEffectiveSeverity_BlastRadiusAdjustment(t *testing.T) {
	tests := []struct {
		name   string
		impact Severity
		radius BlastRadius
		want   Severity
	}{
		{name: "low lowers", impact: SeverityHigh, radius: BlastRadiusLow, want: SeverityMedium},
		{name: "low clamps", impact: SeverityLow, radius: BlastRadiusLow, want: SeverityLow},
		{name: "medium unchanged", impact: SeverityMedium, radius: BlastRadiusMedium, want: SeverityMedium},
		{name: "high raises", impact: SeverityMedium, radius: BlastRadiusHigh, want: SeverityHigh},
		{name: "critical raises two", impact: SeverityLow, radius: BlastRadiusCritical, want: SeverityHigh},
		{name: "critical clamps", impact: SeverityHigh, radius: BlastRadiusCritical, want: SeverityCritical},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := assessedFinding()
			f.Impact, f.BlastRadius = tt.impact, tt.radius
			if got := EffectiveSeverity(f); got != tt.want {
				t.Fatalf("EffectiveSeverity() = %s, want %s", got, tt.want)
			}
		})
	}
}

// WO-20@v3: pin evidence caps across every tier and tier-three reachability state.
func TestEffectiveSeverity_EvidenceCaps(t *testing.T) {
	for _, tt := range []struct {
		name  string
		tier  EvidenceTier
		reach Reachability
		want  Severity
	}{
		{name: "tier zero", tier: EvidenceTierFact, reach: ReachabilityReachable, want: SeverityHigh},
		{name: "tier one", tier: EvidenceTierPolicyShape, reach: ReachabilityReachable, want: SeverityHigh},
		{name: "tier two", tier: EvidenceTierContextualized, reach: ReachabilityReachable, want: SeverityHigh},
		{name: "tier three unknown", tier: EvidenceTierAuthorizationLayers, reach: ReachabilityUnknown, want: SeverityMedium},
		{name: "tier three reachable", tier: EvidenceTierAuthorizationLayers, reach: ReachabilityReachable, want: SeverityCritical},
		{name: "tier four", tier: EvidenceTierSimulated, reach: ReachabilityReachable, want: SeverityCritical},
		{name: "tier five", tier: EvidenceTierWitnessed, reach: ReachabilityReachable, want: SeverityCritical},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := assessedFinding()
			f.Impact, f.BlastRadius, f.EvidenceTier, f.Reachability = SeverityCritical, BlastRadiusCritical, evidenceTier(tt.tier), tt.reach
			if got := EffectiveSeverity(f); got != tt.want {
				t.Fatalf("EffectiveSeverity() = %s, want %s", got, tt.want)
			}
		})
	}
}

// WO-20@v3: pin unknown, unresolved, blocked, and direct-harm behavior.
func TestEffectiveSeverity_RestraintCapsAndExceptions(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Finding)
		want   Severity
	}{
		{name: "unresolved", mutate: func(f *Finding) { f.EvaluatedLayers[LayerSCP] = LayerUnresolved }, want: SeverityMedium},
		{name: "blocked", mutate: func(f *Finding) { f.Reachability = ReachabilityBlocked }, want: SeverityLow},
		{name: "root fact exception", mutate: func(f *Finding) {
			f.ID, f.EvidenceTier, f.Reachability = FindingRootAccessKey, evidenceTier(EvidenceTierFact), ReachabilityUnknown
			f.EvaluatedLayers = completeLayers(LayerNotApplicable)
		}, want: SeverityCritical},
		{name: "witnessed exception", mutate: func(f *Finding) {
			f.EvidenceTier = evidenceTier(EvidenceTierWitnessed)
			f.EvaluatedLayers[LayerSCP] = LayerUnresolved
		}, want: SeverityCritical},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := assessedFinding()
			f.Impact, f.BlastRadius = SeverityCritical, BlastRadiusCritical
			tt.mutate(&f)
			if got := EffectiveSeverity(f); got != tt.want {
				t.Fatalf("EffectiveSeverity() = %s, want %s", got, tt.want)
			}
		})
	}
}

// WO-20@v3: preserve legacy severity and fail closed on partial assessment metadata.
func TestEffectiveSeverity_LegacyAndInvalidPartial(t *testing.T) {
	legacy := Finding{Severity: SeverityCritical}
	if got := EffectiveSeverity(legacy); got != SeverityCritical {
		t.Fatalf("legacy severity = %s, want critical", got)
	}

	partial := Finding{Severity: SeverityHigh, RubricVersion: RubricVersionV1}
	got := NormalizeSeverity(partial)
	if got.Severity != SeverityMedium || got.State != FindingStateIndeterminate {
		t.Fatalf("invalid partial normalized to severity=%s state=%s", got.Severity, got.State)
	}

	partial.Severity = SeverityLow
	if got := EffectiveSeverity(partial); got != SeverityLow {
		t.Fatalf("invalid low partial = %s, want low", got)
	}

	missingState := assessedFinding()
	missingState.State = ""
	missingState.Severity = SeverityCritical
	missingState.Impact = SeverityCritical
	missingState.BlastRadius = BlastRadiusCritical
	if got := NormalizeSeverity(missingState); got.Severity != SeverityMedium || got.State != FindingStateIndeterminate {
		t.Fatalf("missing state normalized to severity=%s state=%s", got.Severity, got.State)
	}
}

// WO-20@v3: explicit tier zero must count as assessment data while a legacy finding does not.
func TestHasAssessment(t *testing.T) {
	if HasAssessment(Finding{Severity: SeverityCritical}) {
		t.Fatal("legacy finding unexpectedly has assessment metadata")
	}
	if !HasAssessment(Finding{EvidenceTier: evidenceTier(EvidenceTierFact)}) {
		t.Fatal("explicit tier-zero finding must have assessment metadata")
	}
}

// WO-20@v3: reject missing, invalid, and extra authorization layers.
func TestEffectiveSeverity_InvalidLayerMetadata(t *testing.T) {
	for _, mutate := range []func(*Finding){
		func(f *Finding) { delete(f.EvaluatedLayers, LayerSCP) },
		func(f *Finding) { f.EvaluatedLayers[LayerSCP] = LayerStatus("invalid") },
		func(f *Finding) { f.EvaluatedLayers[AuthorizationLayer("extra")] = LayerEvaluated },
	} {
		f := assessedFinding()
		f.Severity = SeverityCritical
		mutate(&f)
		if got := NormalizeSeverity(f); got.Severity != SeverityMedium || got.State != FindingStateIndeterminate {
			t.Fatalf("invalid metadata normalized to severity=%s state=%s", got.Severity, got.State)
		}
	}
}
