package report

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/ppiankov/iamspectre/internal/iam"
)

// WO-102@v3: restrict headline derivation to reviewed numeric metadata keys.
var reportNotableFactKeys = []struct {
	label string
	keys  []string
}{
	{label: "Oldest credential", keys: []string{"days_old"}},
	{label: "Longest inactivity", keys: []string{"days_since", "days_since_activity", "days_since_console_activity", "days_since_use"}},
}

// WO-102@v3: render a complete, deterministic Markdown artifact for customer delivery.
func (r *ReportReporter) Generate(data Data) error {
	w := &errWriter{w: r.Writer}

	w.println("# iamspectre IAM Audit Report")
	w.println("")
	writeReportExecutiveSummary(w, data)
	writeReportFindings(w, data.Findings)
	writeReportCoverage(w, data.Coverage)
	writeReportErrors(w, data.Errors)
	writeReportMethodology(w, data)

	return w.err
}

// WO-102@v3: expose scan completeness beside severity totals so zero findings cannot imply full coverage.
func writeReportExecutiveSummary(w *errWriter, data Data) {
	completeness := "complete"
	if len(data.Coverage.Gaps) > 0 || len(data.Errors) > 0 {
		completeness = "incomplete"
	}

	w.println("## Executive summary")
	w.println("")
	w.printf("- Audit completeness: %s\n", completeness)
	w.printf("- Principals scanned: %d\n", data.Summary.TotalPrincipalsScanned)
	w.printf("- Findings: %d\n", data.Summary.TotalFindings)
	for _, severity := range orderedSummarySeverities(data.Summary.BySeverity) {
		w.printf("- %s severity: %d\n", markdownText(reportSeverityTitle(severity)), data.Summary.BySeverity[severity])
	}

	if facts := reportNotableFacts(data.Findings); len(facts) > 0 {
		w.println("")
		w.println("### Notable facts")
		w.println("")
		for _, fact := range facts {
			w.printf("- %s\n", fact)
		}
	}
	w.println("")
}

// WO-102@v3: preserve extension severities while producing a readable summary label.
func reportSeverityTitle(severity string) string {
	if severity == "" {
		return "Unknown"
	}
	runes := []rune(severity)
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}

// WO-102@v3: derive headline facts only from explicitly supported numeric evidence.
func reportNotableFacts(findings []iam.Finding) []string {
	facts := make([]string, 0, len(reportNotableFactKeys))
	for _, definition := range reportNotableFactKeys {
		maximum, found := 0.0, false
		for _, finding := range findings {
			for _, key := range definition.keys {
				value, ok := reportNumber(finding.Metadata[key])
				if ok && (!found || value > maximum) {
					maximum, found = value, true
				}
			}
		}
		if found {
			facts = append(facts, fmt.Sprintf("%s: %g days", definition.label, maximum))
		}
	}
	return facts
}

// WO-102@v3: reject non-numeric metadata rather than inferring notable facts from strings.
func reportNumber(value any) (float64, bool) {
	switch number := value.(type) {
	case int:
		return float64(number), true
	case int8:
		return float64(number), true
	case int16:
		return float64(number), true
	case int32:
		return float64(number), true
	case int64:
		return float64(number), true
	case uint:
		return float64(number), true
	case uint8:
		return float64(number), true
	case uint16:
		return float64(number), true
	case uint32:
		return float64(number), true
	case uint64:
		return float64(number), true
	case float32:
		return float64(number), true
	case float64:
		return number, true
	default:
		return 0, false
	}
}

// WO-102@v3: retain full finding evidence and recommendations without terminal-oriented truncation.
func writeReportFindings(w *errWriter, input []iam.Finding) {
	w.println("## Findings")
	w.println("")
	if len(input) == 0 {
		w.println("No findings met the configured severity filter.")
		w.println("")
		return
	}

	findings := append([]iam.Finding(nil), input...)
	sort.Slice(findings, func(left, right int) bool {
		return findingTextLess(findings[left], findings[right])
	})
	for index, finding := range findings {
		w.printf("### %d. %s (%s)\n", index+1, markdownText(string(finding.ID)), markdownText(strings.ToUpper(string(finding.Severity))))
		w.println("")
		w.printf("- Resource type: %s\n", markdownText(string(finding.ResourceType)))
		w.printf("- Resource ID: %s\n", markdownText(finding.ResourceID))
		if finding.ResourceName != "" {
			w.printf("- Resource name: %s\n", markdownText(finding.ResourceName))
		}
		w.printf("- Risk rationale: %s\n", reportRiskRationale(finding.Severity))
		w.printf("- Evidence: %s\n", markdownText(finding.Message))
		w.printf("- Recommendation: %s\n", markdownText(finding.Recommendation))
		writeReportMetadata(w, finding.Metadata)
		w.println("")
	}
}

// WO-102@v3: select exactly one bounded rationale from the finding severity.
func reportRiskRationale(severity iam.Severity) string {
	switch severity {
	case iam.SeverityCritical:
		return "Critical evidence indicates unrestricted or immediate high-consequence access risk."
	case iam.SeverityHigh:
		return "High-severity evidence indicates broad access or a material control failure."
	case iam.SeverityMedium:
		return "Medium-severity evidence indicates elevated exposure that warrants planned remediation."
	case iam.SeverityLow:
		return "Low-severity evidence indicates a limited hardening opportunity."
	default:
		return "The scanner supplied an unrecognized severity; review the evidence directly."
	}
}

// WO-102@v3: sort evidence keys and use a stable marker for unsupported metadata shapes.
func writeReportMetadata(w *errWriter, metadata map[string]any) {
	if len(metadata) == 0 {
		return
	}
	keys := make([]string, 0, len(metadata))
	for key := range metadata {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	w.println("- Evidence metadata:")
	for _, key := range keys {
		w.printf("  - %s: %s\n", markdownText(key), reportMetadataValue(metadata[key]))
	}
}

// WO-102@v3: render reviewed scalar evidence and mark unsupported shapes deterministically.
func reportMetadataValue(value any) string {
	switch typed := value.(type) {
	case nil:
		return "null"
	case string:
		return markdownText(typed)
	case bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return markdownText(fmt.Sprint(typed))
	case time.Time:
		return typed.UTC().Format(time.RFC3339)
	case *time.Time:
		if typed == nil {
			return "null"
		}
		return typed.UTC().Format(time.RFC3339)
	case []string:
		values := make([]string, len(typed))
		for index, item := range typed {
			values[index] = markdownText(item)
		}
		return strings.Join(values, ", ")
	default:
		return fmt.Sprintf("<unsupported:%s>", reflect.TypeOf(value).Kind())
	}
}

// WO-102@v3: coverage remains a first-class report plane rather than an inferred finding.
func writeReportCoverage(w *errWriter, manifest CoverageManifest) {
	if len(manifest.Gaps) == 0 {
		return
	}
	gaps := append([]CoverageGap(nil), manifest.Gaps...)
	sort.Slice(gaps, func(left, right int) bool {
		leftKey := gaps[left].Capability + "\x00" + gaps[left].Scope + "\x00" + gaps[left].Cause
		rightKey := gaps[right].Capability + "\x00" + gaps[right].Scope + "\x00" + gaps[right].Cause
		return leftKey < rightKey
	})

	w.println("## Coverage gaps")
	w.println("")
	w.printf("Evaluable opportunities: %d/%d\n", manifest.EvaluableOpportunities, manifest.TotalOpportunities)
	w.println("")
	for _, gap := range gaps {
		if len(gap.AffectedFindings) == 0 {
			// WO-128@v2: source-level coverage has no honest affected class or maximum consequence.
			w.printf("- %s [%s]: %s; affected=none; evaluable=%d/%d\n",
				markdownText(gap.Capability), markdownText(gap.Scope), markdownText(gap.Cause),
				gap.EvaluableCount, gap.TotalCount)
			continue
		}
		w.printf("- %s [%s]: %s; affected=%s; evaluable=%d/%d; maximum consequence=%s\n",
			markdownText(gap.Capability), markdownText(gap.Scope), markdownText(gap.Cause),
			markdownText(reportAffectedFindings(gap.AffectedFindings)), gap.EvaluableCount, gap.TotalCount,
			markdownText(string(gap.MaxConsequence)))
	}
	w.println("")
}

// WO-102@v3: render coverage classes in stable finding-ID order.
func reportAffectedFindings(input []AffectedFindingClass) string {
	affected := append([]AffectedFindingClass(nil), input...)
	sort.Slice(affected, func(left, right int) bool {
		return affected[left].FindingID < affected[right].FindingID
	})
	values := make([]string, 0, len(affected))
	for _, item := range affected {
		values = append(values, fmt.Sprintf("%s=%d", item.FindingID, item.Count))
	}
	return strings.Join(values, ",")
}

// WO-102@v3: preserve scanner failures in the deliverable even when no finding was evaluable.
func writeReportErrors(w *errWriter, input []string) {
	if len(input) == 0 {
		return
	}
	errors := append([]string(nil), input...)
	sort.Strings(errors)
	w.println("## Errors")
	w.println("")
	w.printf("Reported errors: %d\n", len(errors))
	w.println("")
	for _, scanError := range errors {
		w.printf("- %s\n", markdownText(scanError))
	}
	w.println("")
}

// WO-102@v3: state scope and read-only behavior explicitly in every standalone artifact.
func writeReportMethodology(w *errWriter, data Data) {
	w.println("## Scope and methodology")
	w.println("")
	w.printf("- Tool: %s %s\n", markdownText(data.Tool), markdownText(data.Version))
	w.printf("- Target: %s (%s)\n", markdownText(data.Target.Type), markdownText(data.Target.URIHash))
	w.printf("- Cloud: %s\n", markdownText(data.Config.Cloud))
	w.printf("- Stale threshold: %d days\n", data.Config.StaleDays)
	if data.Config.SeverityMin != "" {
		w.printf("- Severity filter: %s\n", markdownText(data.Config.SeverityMin))
	}
	w.printf("- Scanned at: %s\n", data.Timestamp.UTC().Format(time.RFC3339))
	w.println("- Method: read-only cloud control-plane inspection; iamspectre does not modify IAM resources.")
}

// WO-102@v3: flatten controls and escape Markdown delimiters at the untrusted-content boundary.
func markdownText(value string) string {
	value = strings.Map(func(character rune) rune {
		if unicode.IsControl(character) {
			return ' '
		}
		return character
	}, value)
	value = strings.Join(strings.Fields(value), " ")
	replacer := strings.NewReplacer(
		"\\", "\\\\", "*", "\\*", "_", "\\_", "[", "\\[", "]", "\\]",
		"(", "\\(", ")", "\\)", "#", "\\#", "<", "\\<", ">", "\\>",
		"`", "\\`", "|", "\\|",
	)
	return replacer.Replace(value)
}
