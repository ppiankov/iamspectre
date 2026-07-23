package report

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ppiankov/iamspectre/internal/analyzer"
	"github.com/ppiankov/iamspectre/internal/iam"
)

// WO-102@v3: pin customer-facing Markdown bytes with a fixed clock and unordered input evidence.
func TestReportReporter_Golden(t *testing.T) {
	var output bytes.Buffer
	if err := (&ReportReporter{Writer: &output}).Generate(reportFixture()); err != nil {
		t.Fatalf("generate: %v", err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "report.golden.md"))
	if err != nil {
		t.Fatalf("read golden: %v\noutput:\n%s", err, output.String())
	}
	want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n")) // WO-102@v3: compare canonical report bytes across Git checkout line endings.
	if output.String() != string(want) {
		t.Fatalf("report mismatch\n--- got ---\n%s\n--- want ---\n%s", output.String(), want)
	}
}

// WO-102@v3: untrusted finding content cannot create Markdown structure or retain controls.
func TestReportReporter_EscapesUntrustedContent(t *testing.T) {
	data := reportFixture()
	data.Findings = []iam.Finding{{
		ID: iam.FindingNoMFA, Severity: iam.Severity("high\n## injected-severity"), ResourceType: iam.ResourceIAMUser,
		ResourceID: "alice\n## injected", ResourceName: "[alice](https://example.invalid)",
		Message: "unsafe\r\n## heading *bold*", Recommendation: "use `MFA` | now",
		Metadata: map[string]any{"arbitrary_days": 9999, "nested": struct{}{}},
	}}
	data.Summary.TotalFindings = 1
	data.Summary.BySeverity = map[string]int{"high\n## injected-summary": 1}

	var output bytes.Buffer
	if err := (&ReportReporter{Writer: &output}).Generate(data); err != nil {
		t.Fatalf("generate: %v", err)
	}
	got := output.String()
	if strings.Contains(got, "\n## injected") || strings.Contains(got, "\n## heading") ||
		!strings.Contains(got, `\[alice\]\(https://example.invalid\)`) ||
		!strings.Contains(got, `\*bold\*`) || !strings.Contains(got, "<unsupported:struct>") ||
		strings.Contains(got, "9999 days") {
		t.Fatalf("unsafe or nondeterministic Markdown output:\n%s", got)
	}
}

// WO-102@v3: zero findings cannot hide incomplete evidence or scanner errors.
func TestReportReporter_EmptyFindingsPreservesPartialAuditEvidence(t *testing.T) {
	data := reportFixture()
	data.Findings = nil
	data.Summary.TotalFindings = 0
	data.Summary.BySeverity = nil

	var output bytes.Buffer
	if err := (&ReportReporter{Writer: &output}).Generate(data); err != nil {
		t.Fatalf("generate: %v", err)
	}
	got := output.String()
	for _, want := range []string{"No findings met the configured severity filter.", "## Coverage gaps", "## Errors", "Reported errors: 1"} {
		if !strings.Contains(got, want) {
			t.Fatalf("output missing %q:\n%s", want, got)
		}
	}
}

// WO-128@v2: Markdown coverage never fabricates an affected finding or consequence for source failures.
func TestReportReporter_SourceCoverageGap(t *testing.T) {
	data := reportFixture()
	data.Findings = nil
	data.Summary.TotalFindings = 0
	data.Coverage = CoverageManifest{Gaps: []CoverageGap{{
		Capability: "aws_eks_pod_identity_associations",
		Cause:      "access_denied",
		Scope:      "aws-region:us-east-1",
	}}}

	var output bytes.Buffer
	if err := (&ReportReporter{Writer: &output}).Generate(data); err != nil {
		t.Fatalf("generate report: %v", err)
	}
	const want = "- aws\\_eks\\_pod\\_identity\\_associations [aws-region:us-east-1]: access\\_denied; affected=none; evaluable=0/0"
	if !strings.Contains(output.String(), want) {
		t.Fatalf("report missing source gap %q:\n%s", want, output.String())
	}
	if strings.Contains(output.String(), "maximum consequence=") {
		t.Fatalf("report fabricated source consequence:\n%s", output.String())
	}
}

// WO-102@v3: output failures remain visible to the shared command boundary.
func TestReportReporter_WriterError(t *testing.T) {
	want := errors.New("write failed")
	err := (&ReportReporter{Writer: reportFailingWriter{err: want}}).Generate(reportFixture())
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

// WO-102@v3: inject a deterministic writer failure without filesystem behavior.
type reportFailingWriter struct{ err error }

// WO-102@v3: return the injected artifact-write failure unchanged.
func (w reportFailingWriter) Write([]byte) (int, error) { return 0, w.err }

// WO-102@v3: exercise ordering, notable facts, coverage, errors, and long untruncated fields.
func reportFixture() Data {
	timestamp := time.Date(2026, time.July, 21, 8, 9, 10, 0, time.UTC)
	longMessage := strings.Repeat("retain this complete evidence ", 5) + "without truncation"
	longRecommendation := strings.Repeat("review this permission carefully ", 5) + "before changing access"
	return Data{
		Tool: "iamspectre", Version: "0.4.2", Timestamp: timestamp,
		Target: Target{Type: "aws-account", URIHash: "sha256:customer"},
		Config: ReportConfig{Cloud: "aws", StaleDays: 90, SeverityMin: "low"},
		Findings: []iam.Finding{
			{
				ID: iam.FindingStaleAccessKey, Severity: iam.SeverityMedium,
				ResourceType: iam.ResourceIAMUser, ResourceID: "access-key-redacted", ResourceName: "alice-key",
				Message: longMessage, Recommendation: longRecommendation,
				Metadata: map[string]any{"days_old": 3650, "days_since_use": 365, "last_used": "unknown"},
			},
			{
				ID: iam.FindingWildcardPolicy, Severity: iam.SeverityCritical,
				ResourceType: iam.ResourceIAMPolicy, ResourceID: "arn:aws:iam::123456789012:policy/admin", ResourceName: "admin",
				Message:        "Policy grants unrestricted actions and resources",
				Recommendation: "Restrict actions and resources before the next review",
				Metadata:       map[string]any{"wildcard_action": true, "wildcard_resource": true},
			},
		},
		Summary: analyzer.Summary{
			TotalPrincipalsScanned: 42,
			TotalFindings:          2,
			BySeverity:             map[string]int{"medium": 1, "critical": 1},
		},
		Coverage: CoverageManifest{
			UniqueMissingCapabilities: 1, EvaluableOpportunities: 41, TotalOpportunities: 42,
			Gaps: []CoverageGap{{
				Capability: "aws_role_last_used", Cause: "evidence_unavailable", Scope: "aws-account:123456789012",
				AffectedFindings: []AffectedFindingClass{{FindingID: iam.FindingUnusedRole, Count: 1}},
				EvaluableCount:   41, TotalCount: 42, MaxConsequence: iam.SeverityMedium,
			}},
		},
		Errors: []string{"fetch policy version: access denied"},
	}
}
