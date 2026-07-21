package commands

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ppiankov/iamspectre/internal/config"
	"github.com/ppiankov/iamspectre/internal/iam"
	"github.com/spf13/cobra"
)

// WO-11@v2: pin exact persisted-to-runtime exclusion conversion.
func TestToExcludeConfig(t *testing.T) {
	tests := []struct {
		name       string
		exclude    config.Exclude
		principals map[string]bool
		resources  map[string]bool
	}{
		{name: "empty", principals: map[string]bool{}, resources: map[string]bool{}},
		{
			name: "principals resources and duplicates",
			exclude: config.Exclude{
				Principals:  []string{"alice", "alice", "bob"},
				ResourceIDs: []string{"resource-1", "resource-1"},
			},
			principals: map[string]bool{"alice": true, "bob": true},
			resources:  map[string]bool{"resource-1": true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toExcludeConfig(tt.exclude)
			if !mapsEqual(got.Principals, tt.principals) {
				t.Fatalf("principals = %#v, want %#v", got.Principals, tt.principals)
			}
			if !mapsEqual(got.ResourceIDs, tt.resources) {
				t.Fatalf("resource IDs = %#v, want %#v", got.ResourceIDs, tt.resources)
			}
		})
	}
}

// WO-11@v2: compare exclusion lookup maps without changing their representation.
func mapsEqual(got, want map[string]bool) bool {
	if len(got) != len(want) {
		return false
	}
	for key, value := range want {
		if got[key] != value {
			return false
		}
	}
	return true
}

func TestEnhanceError_NoCredentials(t *testing.T) {
	err := enhanceError("test", errors.New("NoCredentialProviders: no valid providers"))
	if !strings.Contains(err.Error(), "hint:") {
		t.Fatal("expected hint for NoCredentialProviders")
	}
	if !strings.Contains(err.Error(), "AWS_PROFILE") {
		t.Fatal("expected AWS_PROFILE suggestion")
	}
}

func TestEnhanceError_ExpiredToken(t *testing.T) {
	err := enhanceError("test", errors.New("ExpiredToken: token expired"))
	if !strings.Contains(err.Error(), "hint:") {
		t.Fatal("expected hint for ExpiredToken")
	}
}

func TestEnhanceError_AccessDenied(t *testing.T) {
	err := enhanceError("test", errors.New("AccessDenied: not authorized"))
	if !strings.Contains(err.Error(), "iamspectre init") {
		t.Fatal("expected iamspectre init suggestion")
	}
}

func TestEnhanceError_GCPCredentials(t *testing.T) {
	err := enhanceError("test", errors.New("could not find default credentials"))
	if !strings.Contains(err.Error(), "gcloud auth") {
		t.Fatal("expected gcloud auth suggestion")
	}
}

// WO-101@v3: pin every remaining cloud hint without changing or exposing the source error.
func TestEnhanceErrorAdditionalHints(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		want     string
	}{
		{name: "expired request", provider: "RequestExpired: clock skew", want: "system clock"},
		{name: "throttling", provider: "Throttling: rate exceeded", want: "rate limit"},
		{name: "Azure authentication", provider: "AADSTS700016: application missing", want: "az login"},
		{name: "Graph authorization", provider: "Authorization_RequestDenied: denied", want: "Graph API permissions"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := enhanceError("scan", errors.New(test.provider))
			if !strings.Contains(err.Error(), "hint:") || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %q, want hint containing %q", err, test.want)
			}
		})
	}
}

func TestEnhanceError_NoHint(t *testing.T) {
	err := enhanceError("test action", errors.New("some random error"))
	if strings.Contains(err.Error(), "hint:") {
		t.Fatal("expected no hint for unknown error")
	}
	if !strings.Contains(err.Error(), "test action") {
		t.Fatal("expected action in error message")
	}
}

// WO-25@v2: keep reporter construction coverage on the writer-based boundary.
// WO-102@v3: include the customer Markdown reporter in the valid format contract.
func TestSelectReporter_ValidFormats(t *testing.T) {
	formats := []string{"text", "report", "json", "sarif", "spectrehub"}
	for _, f := range formats {
		t.Run(f, func(t *testing.T) {
			r, err := selectReporter(f, &bytes.Buffer{})
			if err != nil {
				t.Fatalf("unexpected error for format %s: %v", f, err)
			}
			if r == nil {
				t.Fatalf("expected non-nil reporter for format %s", f)
			}
		})
	}
}

// WO-25@v2: pin rejection before any output resource is acquired.
func TestSelectReporter_InvalidFormat(t *testing.T) {
	_, err := selectReporter("csv", &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Fatal("expected unsupported format message")
	}
}

// WO-27@v2: pin common flag metadata without mutating package-global commands.
func TestRegisterCommonScanFlags(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	var flags commonScanFlags
	registerCommonScanFlags(cmd, &flags)
	assertCommonFlagMetadata(t, cmd)
}

// WO-27@v2: apply the exact shared flag contract to every fresh provider command.
// WO-102@v3: pin report format discoverability in shared flag help.
func assertCommonFlagMetadata(t *testing.T, cmd *cobra.Command) {
	t.Helper()
	tests := []struct {
		name, def, shorthand, valueType, usage string
	}{
		{name: "stale-days", def: "90", valueType: "int", usage: "Inactivity threshold (days)"},
		{name: "severity-min", def: "low", valueType: "string", usage: "Minimum severity to report: critical, high, medium, low"},
		{name: "format", def: "text", valueType: "string", usage: "Output format: text, report, json, sarif, spectrehub"},
		{name: "output", def: "", shorthand: "o", valueType: "string", usage: "Output file path (default: stdout)"},
		{name: "timeout", def: "5m0s", valueType: "duration", usage: "Scan timeout"},
	}
	for _, tt := range tests {
		flag := cmd.Flags().Lookup(tt.name)
		if flag == nil || flag.DefValue != tt.def || flag.Shorthand != tt.shorthand || flag.Value.Type() != tt.valueType || flag.Usage != tt.usage {
			t.Fatalf("flag %s = %#v, want default %q shorthand %q type %q usage %q", tt.name, flag, tt.def, tt.shorthand, tt.valueType, tt.usage)
		}
	}
}

// WO-27@v2: verify fresh provider commands expose exact shared metadata and only local flags.
func TestProviderCommonFlagMatrix(t *testing.T) {
	providers := []struct {
		name          string
		register      func(*cobra.Command)
		providerFlags []string
		foreignFlags  []string
	}{
		{name: "aws", register: func(cmd *cobra.Command) { registerAWSFlags(cmd, &awsScanFlags{}) }, providerFlags: []string{"profile", "include-service-linked-roles"}, foreignFlags: []string{"project", "tenant", "include-guests"}},
		{name: "gcp", register: func(cmd *cobra.Command) { registerGCPFlags(cmd, &gcpScanFlags{}) }, providerFlags: []string{"project"}, foreignFlags: []string{"profile", "tenant", "include-guests", "include-service-linked-roles"}},
		{name: "azure", register: func(cmd *cobra.Command) { registerAzureFlags(cmd, &azureScanFlags{}) }, providerFlags: []string{"tenant", "include-guests"}, foreignFlags: []string{"profile", "project", "include-service-linked-roles"}},
	}
	common := []string{"stale-days", "severity-min", "format", "output", "timeout"}
	for _, provider := range providers {
		t.Run(provider.name, func(t *testing.T) {
			cmd := &cobra.Command{Use: provider.name}
			provider.register(cmd)
			assertCommonFlagMetadata(t, cmd)
			for _, name := range append(common, provider.providerFlags...) {
				if cmd.Flags().Lookup(name) == nil {
					t.Fatalf("missing flag %q", name)
				}
			}
			for _, name := range provider.foreignFlags {
				if cmd.Flags().Lookup(name) != nil {
					t.Fatalf("unexpected foreign flag %q", name)
				}
			}
		})
	}
}

// WO-44@v2: pin the safety-critical AWS-only flag contract.
func TestAWSServiceLinkedRoleFlagMetadata(t *testing.T) {
	cmd := &cobra.Command{Use: "aws"}
	registerAWSFlags(cmd, &awsScanFlags{})
	flag := cmd.Flags().Lookup("include-service-linked-roles")
	if flag == nil || flag.DefValue != "false" || flag.Value.Type() != "bool" ||
		flag.Usage != "Include unused AWS service-linked roles" {
		t.Fatalf("include-service-linked-roles = %#v", flag)
	}
}

// WO-25@v2: pin the shared report envelope and severity filtering with fixed time.
func TestAnalyzeAndReportJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	result := &iam.ScanResult{
		Findings: []iam.Finding{
			{ID: iam.FindingNoMFA, Severity: iam.SeverityCritical, ResourceID: "critical"},
			{ID: iam.FindingUnusedRole, Severity: iam.SeverityLow, ResourceID: "low"},
		},
		Errors: []string{"scan warning"}, PrincipalsScanned: 2,
		CoverageGaps: []iam.CoverageGapObservation{{
			Capability: "activity", Cause: "unavailable", Scope: "account:prod",
			FindingID: iam.FindingUnusedRole, AffectedCount: 1, TotalCount: 1,
			MaxConsequence: iam.SeverityMedium,
		}},
	}
	wantTime := time.Date(2026, time.July, 19, 1, 2, 3, 0, time.UTC)
	err := analyzeAndReport(result, postScanOptions{
		cloud: "aws", targetType: "aws-account", targetID: "prod", staleDays: 30,
		severityMin: "high", format: "json", outputFile: path, timestamp: wantTime,
	})
	if err != nil {
		t.Fatalf("analyzeAndReport: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	findings, ok := decoded["findings"].([]any)
	if !ok || len(findings) != 1 {
		t.Fatalf("findings = %#v, want one high-or-higher finding", decoded["findings"])
	}
	if got := decoded["timestamp"]; got != wantTime.Format(time.RFC3339) {
		t.Fatalf("timestamp = %v, want %s", got, wantTime.Format(time.RFC3339))
	}
	if errorsValue, ok := decoded["errors"].([]any); !ok || len(errorsValue) != 1 || errorsValue[0] != "scan warning" {
		t.Fatalf("errors = %#v, want scan warning", decoded["errors"])
	}
	coverage, ok := decoded["coverage_manifest"].(map[string]any)
	if !ok || coverage["unique_missing_capabilities"] != float64(1) {
		t.Fatalf("coverage_manifest = %#v", decoded["coverage_manifest"])
	}
	target, ok := decoded["target"].(map[string]any)
	if !ok || target["type"] != "aws-account" || target["uri_hash"] != computeTargetHash("prod") {
		t.Fatalf("target = %#v", decoded["target"])
	}
	configValue, ok := decoded["config"].(map[string]any)
	if !ok || configValue["cloud"] != "aws" || configValue["severity_min"] != "high" || configValue["stale_days"] != float64(30) {
		t.Fatalf("config = %#v", decoded["config"])
	}
	summary, ok := decoded["summary"].(map[string]any)
	if !ok || summary["total_principals_scanned"] != float64(2) || summary["total_findings"] != float64(1) {
		t.Fatalf("summary = %#v, want 2 principals and 1 filtered finding", decoded["summary"])
	}
	bySeverity, ok := summary["by_severity"].(map[string]any)
	if !ok || bySeverity["critical"] != float64(1) || len(bySeverity) != 1 {
		t.Fatalf("summary severity = %#v, want critical=1", summary["by_severity"])
	}
}

// WO-25@v2: invalid formats must not create or truncate the requested output.
func TestAnalyzeAndReportValidatesBeforeCreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing.txt")
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := analyzeAndReport(&iam.ScanResult{}, postScanOptions{format: "csv", outputFile: path})
	if err == nil || !strings.Contains(err.Error(), "unsupported format") {
		t.Fatalf("error = %v, want unsupported format", err)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil || string(data) != "keep" {
		t.Fatalf("invalid format changed output: data=%q err=%v", data, readErr)
	}
}

// WO-25@v2: propagate output acquisition failures without partial reporting.
func TestAnalyzeAndReportCreateFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "report.json")
	err := analyzeAndReport(&iam.ScanResult{}, postScanOptions{format: "json", outputFile: path})
	if err == nil || !strings.Contains(err.Error(), "create output file") {
		t.Fatalf("error = %v, want create output file", err)
	}
}

// WO-25@v2: deterministically inject reporter generation failures.
type failingWriter struct{ err error }

// WO-25@v2: return the injected writer failure unchanged.
func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

// WO-25@v2: deterministically inject output close failures.
type closeErrorWriter struct {
	bytes.Buffer
	err error
}

// WO-25@v2: return the injected close failure unchanged.
func (w *closeErrorWriter) Close() error { return w.err }

// WO-25@v2: every reporter format must execute through the shared pipeline.
// WO-102@v3: keep the new report format on that provider-neutral pipeline.
func TestAnalyzeAndReportFormats(t *testing.T) {
	// WO-74@v5: SpectreHub integration uses release metadata accepted by the consumer schema.
	oldVersion := version
	version = "0.1.0"
	t.Cleanup(func() { version = oldVersion })
	for _, format := range []string{"text", "report", "json", "sarif", "spectrehub"} {
		t.Run(format, func(t *testing.T) {
			var output bytes.Buffer
			err := analyzeAndReport(&iam.ScanResult{}, postScanOptions{
				format: format, severityMin: "low", timestamp: time.Unix(0, 0).UTC(), writer: &output,
				targetType: "aws-account",
			})
			if err != nil || output.Len() == 0 {
				t.Fatalf("format %s output=%q err=%v", format, output.String(), err)
			}
		})
	}
}

// WO-102@v3: every provider reaches the customer report through the shared post-scan boundary.
func TestAnalyzeAndReportReportAcrossProviders(t *testing.T) {
	providers := []struct {
		cloud, targetType string
	}{
		{cloud: "aws", targetType: "aws-account"},
		{cloud: "gcp", targetType: "gcp-project"},
		{cloud: "azure", targetType: "azure-tenant"},
	}
	for _, provider := range providers {
		t.Run(provider.cloud, func(t *testing.T) {
			var output bytes.Buffer
			err := analyzeAndReport(&iam.ScanResult{}, postScanOptions{
				cloud: provider.cloud, targetType: provider.targetType, targetID: "customer",
				format: "report", severityMin: "low", timestamp: time.Unix(0, 0).UTC(), writer: &output,
			})
			if err != nil {
				t.Fatalf("analyzeAndReport: %v", err)
			}
			for _, want := range []string{"# iamspectre IAM Audit Report", "- Cloud: " + provider.cloud, "- Target: " + provider.targetType} {
				if !strings.Contains(output.String(), want) {
					t.Fatalf("output missing %q:\n%s", want, output.String())
				}
			}
		})
	}
}

// WO-25@v2: preserve reporter generation errors.
func TestAnalyzeAndReportGenerationFailure(t *testing.T) {
	want := errors.New("write failed")
	err := analyzeAndReport(&iam.ScanResult{}, postScanOptions{
		format: "json", severityMin: "low", writer: failingWriter{err: want},
	})
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

// WO-25@v2: surface close errors after successful generation.
func TestAnalyzeAndReportCloseFailure(t *testing.T) {
	want := errors.New("close failed")
	output := &closeErrorWriter{err: want}
	err := analyzeAndReport(&iam.ScanResult{}, postScanOptions{
		format: "json", severityMin: "low", outputFile: "ignored",
		openOutput: func(string) (io.WriteCloser, error) { return output, nil },
	})
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

// WO-25@v2: keep the primary generation failure when close also fails.
func TestAnalyzeAndReportGenerationErrorPrecedesCloseError(t *testing.T) {
	writeErr := errors.New("write failed")
	closeErr := errors.New("close failed")
	output := struct {
		io.Writer
		io.Closer
	}{Writer: failingWriter{err: writeErr}, Closer: &closeErrorWriter{err: closeErr}}
	err := analyzeAndReport(&iam.ScanResult{}, postScanOptions{
		format: "json", severityMin: "low", outputFile: "ignored",
		openOutput: func(string) (io.WriteCloser, error) { return output, nil },
	})
	if !errors.Is(err, writeErr) || errors.Is(err, closeErr) {
		t.Fatalf("error = %v, want generation error precedence", err)
	}
}

func TestSha256Sum(t *testing.T) {
	result := sha256Sum("test")
	if len(result) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(result))
	}
	// Same input should produce same hash
	result2 := sha256Sum("test")
	for i := range result {
		if result[i] != result2[i] {
			t.Fatal("expected deterministic hash")
		}
	}
}

func TestComputeTargetHash(t *testing.T) {
	hash := computeTargetHash("production")
	if !strings.HasPrefix(hash, "sha256:") {
		t.Fatalf("expected sha256: prefix, got %s", hash)
	}
	if len(hash) < 20 {
		t.Fatal("hash too short")
	}
}
