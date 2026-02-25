package report

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

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

// Generate produces a human-readable text report.
func (r *TextReporter) Generate(data Data) error {
	w := &errWriter{w: r.Writer}

	w.println("iamspectre — IAM Audit Report")
	w.println(strings.Repeat("=", 60))
	w.printf("Tool: %s %s\n", data.Tool, data.Version)
	w.printf("Target: %s\n", data.Target.Type)
	w.printf("Cloud: %s\n", data.Config.Cloud)
	w.printf("Stale threshold: %d days\n", data.Config.StaleDays)
	w.println("")

	if len(data.Findings) == 0 {
		w.println("No findings.")
		return w.err
	}

	tw := tabwriter.NewWriter(r.Writer, 0, 0, 2, ' ', 0)
	ew := &errWriter{w: tw}
	ew.println("SEVERITY\tTYPE\tRESOURCE\tMESSAGE\tRECOMMENDATION")
	ew.println("--------\t----\t--------\t-------\t--------------")

	for _, f := range data.Findings {
		ew.printf("%s\t%s\t%s\t%s\t%s\n",
			severityLabel(f.Severity),
			f.ResourceType,
			truncate(f.ResourceID, 40),
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

	printTextSummary(w, data)
	return w.err
}

func printTextSummary(w *errWriter, data Data) {
	w.println("")
	w.println(strings.Repeat("-", 60))
	w.printf("Principals scanned: %d\n", data.Summary.TotalPrincipalsScanned)
	w.printf("Total findings: %d\n", data.Summary.TotalFindings)

	if len(data.Summary.BySeverity) > 0 {
		w.printf("By severity:")
		for sev, count := range data.Summary.BySeverity {
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

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
