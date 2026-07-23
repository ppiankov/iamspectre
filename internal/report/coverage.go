package report

import (
	"sort"
	"time"

	"github.com/ppiankov/iamspectre/internal/iam"
)

type coverageKey struct {
	capability string
	cause      string
	scope      string
}

type coverageAccumulator struct {
	gap    CoverageGap
	counts map[iam.FindingID]int
}

// WO-70@v4: BuildCoverageManifest deterministically merges raw evidence gaps outside severity filtering.
func BuildCoverageManifest(observations []iam.CoverageGapObservation) CoverageManifest {
	merged := make(map[coverageKey]*coverageAccumulator)
	for _, observation := range observations {
		// WO-128@v2: capability identity is sufficient for honest source-level coverage without a finding class.
		if observation.Capability == "" || observation.Cause == "" || observation.Scope == "" {
			continue
		}
		key := coverageKey{capability: observation.Capability, cause: observation.Cause, scope: observation.Scope}
		accumulator := merged[key]
		if accumulator == nil {
			accumulator = &coverageAccumulator{
				gap: CoverageGap{
					Capability: observation.Capability, Cause: observation.Cause, Scope: observation.Scope,
				},
				counts: make(map[iam.FindingID]int),
			}
			merged[key] = accumulator
		}
		mergeCoverageObservation(accumulator, observation)
	}

	manifest := CoverageManifest{Gaps: make([]CoverageGap, 0, len(merged))}
	capabilities := make(map[string]struct{}, len(merged))
	for _, accumulator := range merged {
		findingIDs := make([]string, 0, len(accumulator.counts))
		for findingID := range accumulator.counts {
			findingIDs = append(findingIDs, string(findingID))
		}
		sort.Strings(findingIDs)
		for _, findingID := range findingIDs {
			id := iam.FindingID(findingID)
			accumulator.gap.AffectedFindings = append(accumulator.gap.AffectedFindings, AffectedFindingClass{
				FindingID: id,
				Count:     accumulator.counts[id],
			})
		}
		manifest.Gaps = append(manifest.Gaps, accumulator.gap)
		manifest.EvaluableOpportunities += accumulator.gap.EvaluableCount
		manifest.TotalOpportunities += accumulator.gap.TotalCount
		capabilities[accumulator.gap.Capability] = struct{}{}
		manifest.OldestEvidence = earlierTime(manifest.OldestEvidence, accumulator.gap.OldestEvidence)
	}
	sort.Slice(manifest.Gaps, func(left, right int) bool {
		if manifest.Gaps[left].Capability != manifest.Gaps[right].Capability {
			return manifest.Gaps[left].Capability < manifest.Gaps[right].Capability
		}
		if manifest.Gaps[left].Scope != manifest.Gaps[right].Scope {
			return manifest.Gaps[left].Scope < manifest.Gaps[right].Scope
		}
		return manifest.Gaps[left].Cause < manifest.Gaps[right].Cause
	})
	manifest.UniqueMissingCapabilities = len(capabilities)
	return manifest
}

// WO-70@v4: merge counts and bounded evidence using order-independent rules.
func mergeCoverageObservation(accumulator *coverageAccumulator, observation iam.CoverageGapObservation) {
	if observation.FindingID != "" {
		// WO-128@v2: source-level gaps remain valid without fabricating an affected finding class.
		accumulator.counts[observation.FindingID] += nonNegative(observation.AffectedCount)
	}
	accumulator.gap.EvaluableCount += nonNegative(observation.EvaluableCount)
	accumulator.gap.TotalCount += nonNegative(observation.TotalCount)
	accumulator.gap.ObservationWindow = stableNonEmpty(accumulator.gap.ObservationWindow, observation.ObservationWindow)
	accumulator.gap.FeatureStage = stableNonEmpty(accumulator.gap.FeatureStage, observation.FeatureStage)
	accumulator.gap.OldestEvidence = earlierTime(accumulator.gap.OldestEvidence, observation.OldestEvidence)
	if iam.SeverityRank(observation.MaxConsequence) > iam.SeverityRank(accumulator.gap.MaxConsequence) {
		accumulator.gap.MaxConsequence = observation.MaxConsequence
	}
}

// WO-70@v4: invalid negative counts cannot reduce independently reported coverage totals.
func nonNegative(value int) int {
	if value < 0 {
		return 0
	}
	return value
}

// WO-70@v4: conflicting descriptive values converge independently of scanner order.
func stableNonEmpty(current, candidate string) string {
	if current == "" || candidate != "" && candidate < current {
		return candidate
	}
	return current
}

// WO-70@v4: the oldest known evidence is the conservative freshness boundary.
func earlierTime(current, candidate *time.Time) *time.Time {
	if candidate == nil {
		return current
	}
	if current == nil || candidate.Before(*current) {
		copy := candidate.UTC()
		return &copy
	}
	return current
}
