package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ppiankov/iamspectre/internal/iam"
)

// errWriter wraps an io.Writer and captures the first error.
type errWriter struct {
	w   io.Writer
	err error
}

func (ew *errWriter) printf(format string, args ...any) {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprintf(ew.w, format, args...)
}

func (ew *errWriter) println(s string) {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprintln(ew.w, s)
}

// WO-31@v2: keep the text report self-describing and preserve partial-scan evidence.
// WO-42@v2, WO-43@v2, WO-47: render deterministic rows with complete, valid field identity.
func (r *TextReporter) Generate(data Data) error {
	w := &errWriter{w: r.Writer}

	w.println("iamspectre — IAM Audit Report")
	w.println(strings.Repeat("=", 60))
	w.printf("Tool: %s %s\n", data.Tool, data.Version)
	w.printf("Target: %s\n", data.Target.Type)
	w.printf("Cloud: %s\n", data.Config.Cloud)
	w.printf("Stale threshold: %d days\n", data.Config.StaleDays)
	w.printf("Scanned at: %s\n", data.Timestamp.UTC().Format(time.RFC3339))
	if data.Config.SeverityMin != "" {
		w.printf("Severity filter: %s\n", data.Config.SeverityMin)
	}
	w.println("")

	if len(data.Findings) == 0 {
		w.println("No findings.")
		printTextCoverage(w, data.Coverage)
		printTextSummary(w, data)
		return w.err
	}

	tw := tabwriter.NewWriter(r.Writer, 0, 0, 2, ' ', 0)
	ew := &errWriter{w: tw}
	// WO-34@v2: expose the stable finding classification in text output.
	ew.println("FINDING_ID\tSEVERITY\tTYPE\tRESOURCE\tMESSAGE\tRECOMMENDATION")
	ew.println("----------\t--------\t----\t--------\t-------\t--------------")

	// WO-42@v2: sort a copy by a total order so rendering is deterministic and side-effect free.
	findings := append([]iam.Finding(nil), data.Findings...)
	sort.Slice(findings, func(left, right int) bool {
		return findingTextLess(findings[left], findings[right])
	})
	for _, f := range findings {
		ew.printf("%s\t%s\t%s\t%s\t%s\t%s\n",
			f.ID,
			severityLabel(f.Severity),
			f.ResourceType,
			f.ResourceID, // WO-43@v2: preserve the complete actionable resource identity.
			truncate(f.Message, 50),
			truncate(f.Recommendation, 50),
		)
	}

	if ew.err != nil {
		return ew.err
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	printTextCoverage(w, data.Coverage)
	printTextSummary(w, data)
	return w.err
}

// WO-70@v4: render coverage gaps as a second plane, never as finding rows.
func printTextCoverage(w *errWriter, manifest CoverageManifest) {
	if len(manifest.Gaps) == 0 {
		return
	}
	w.println("")
	w.println("Coverage gaps:")
	for _, gap := range manifest.Gaps {
		classes := make([]string, 0, len(gap.AffectedFindings))
		for _, affected := range gap.AffectedFindings {
			classes = append(classes, fmt.Sprintf("%s=%d", affected.FindingID, affected.Count))
		}
		w.printf("  - %s [%s]: %s; affected=%s; evaluable=%d/%d; max=%s\n",
			gap.Capability, gap.Scope, gap.Cause, strings.Join(classes, ","),
			gap.EvaluableCount, gap.TotalCount, gap.MaxConsequence)
	}
}

// WO-42@v2: keep summary output deterministic alongside the finding table.
func printTextSummary(w *errWriter, data Data) {
	w.println("")
	w.println(strings.Repeat("-", 60))
	w.printf("Principals scanned: %d\n", data.Summary.TotalPrincipalsScanned)
	w.printf("Total findings: %d\n", data.Summary.TotalFindings)

	if len(data.Summary.BySeverity) > 0 {
		w.printf("By severity:")
		// WO-42@v2: map iteration must not reintroduce nondeterministic report bytes.
		for _, sev := range orderedSummarySeverities(data.Summary.BySeverity) {
			count := data.Summary.BySeverity[sev]
			w.printf(" %s=%d", sev, count)
		}
		w.println("")
	}

	if len(data.Errors) > 0 {
		w.printf("\nErrors (%d):\n", len(data.Errors))
		for _, e := range data.Errors {
			w.printf("  - %s\n", e)
		}
	}
}

// WO-42@v2: define a total finding order independent of scanner aggregation order.
func findingTextLess(left, right iam.Finding) bool {
	leftRank, rightRank := iam.SeverityRank(left.Severity), iam.SeverityRank(right.Severity)
	if leftRank != rightRank {
		return leftRank > rightRank
	}
	leftFields := []string{
		string(left.Severity), string(left.ID), string(left.ResourceType),
		left.ResourceID, left.Message, left.Recommendation,
	}
	rightFields := []string{
		string(right.Severity), string(right.ID), string(right.ResourceType),
		right.ResourceID, right.Message, right.Recommendation,
	}
	for index := range leftFields {
		if leftFields[index] != rightFields[index] {
			return leftFields[index] < rightFields[index]
		}
	}
	return false
}

// WO-42@v2: render known severities by risk and unknown extensions lexicographically.
func orderedSummarySeverities(counts map[string]int) []string {
	known := []string{
		string(iam.SeverityCritical),
		string(iam.SeverityHigh),
		string(iam.SeverityMedium),
		string(iam.SeverityLow),
	}
	ordered := make([]string, 0, len(counts))
	for _, severity := range known {
		if _, exists := counts[severity]; exists {
			ordered = append(ordered, severity)
		}
	}
	unknown := make([]string, 0, len(counts)-len(ordered))
	for severity := range counts {
		if severity != string(iam.SeverityCritical) &&
			severity != string(iam.SeverityHigh) &&
			severity != string(iam.SeverityMedium) &&
			severity != string(iam.SeverityLow) {
			unknown = append(unknown, severity)
		}
	}
	sort.Strings(unknown)
	return append(ordered, unknown...)
}

func severityLabel(s iam.Severity) string {
	switch s {
	case iam.SeverityCritical:
		return "CRIT"
	case iam.SeverityHigh:
		return "HIGH"
	case iam.SeverityMedium:
		return "MED"
	case iam.SeverityLow:
		return "LOW"
	default:
		return string(s)
	}
}

// WO-48: bound human-readable fields without splitting UTF-8 code points.
func truncate(s string, max int) string {
	runes := []rune(s) // WO-48: byte slicing can corrupt multibyte report fields.
	if len(runes) <= max {
		return s
	}
	if max <= 3 {
		return string(runes[:max])
	}
	return string(runes[:max-3]) + "..."
}
