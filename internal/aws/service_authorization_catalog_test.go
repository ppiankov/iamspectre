package aws

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testCatalogSourceURL   = "https://servicereference.us-east-1.amazonaws.com/v1/ssm/ssm.json"
	testCatalogRetrievedAt = "2026-07-20T08:15:00Z"
)

// WO-64@v3: pin examples of both applicability classes the official JSON can prove.
func TestResourceApplicabilityCatalog(t *testing.T) {
	tests := []struct {
		action string
		want   ResourceApplicability
	}{
		{action: "ssm:GetDocument", want: ResourceApplicabilitySupported},
		{action: "ssm:AddTagsToResource", want: ResourceApplicabilitySupported},
		{action: "ssm:DescribeActivations", want: ResourceApplicabilityNone},
	}
	for _, tt := range tests {
		if got := resourceApplicabilityCatalog[tt.action]; got != tt.want {
			t.Fatalf("catalog[%q] = %q, want %q", tt.action, got, tt.want)
		}
	}
}

// WO-64@v3: checked-in generated data must be byte-identical to offline regeneration.
func TestServiceAuthorizationCatalogReproducible(t *testing.T) {
	first := generateCatalog(t, "testdata/service_authorization_reference.json", testCatalogSourceURL, testCatalogRetrievedAt)
	second := generateCatalog(t, "testdata/service_authorization_reference.json", testCatalogSourceURL, testCatalogRetrievedAt)
	if !bytes.Equal(first, second) {
		t.Fatal("repeated generation produced different bytes")
	}
	checkedIn, err := os.ReadFile("service_authorization_catalog.go")
	if err != nil {
		t.Fatalf("read checked-in catalog: %v", err)
	}
	checkedIn = normalizeCatalogCheckout(checkedIn)
	if !bytes.Equal(first, checkedIn) {
		t.Fatal("checked-in catalog differs from deterministic regeneration")
	}
	for _, marker := range []string{"// Source: " + testCatalogSourceURL, "// Retrieved: " + testCatalogRetrievedAt, "// Schema: AWS Service Reference v1.4", "// SHA-256:"} {
		if !bytes.Contains(first, []byte(marker)) {
			t.Fatalf("generated header missing %s", marker)
		}
	}
	if resourceApplicabilityCatalogDigest == "" || !bytes.Contains(first, []byte(`const resourceApplicabilityCatalogDigest = "`+resourceApplicabilityCatalogDigest+`"`)) {
		t.Fatal("generated catalog does not expose its pinned input digest")
	}
}

// WO-64@v3: normalize only Git's CRLF checkout representation, never fixture evidence.
func normalizeCatalogCheckout(content []byte) []byte {
	return bytes.ReplaceAll(content, []byte("\r\n"), []byte("\n"))
}

// WO-64@v3: pin identical comparison content for LF and CRLF checkouts.
func TestNormalizeCatalogCheckout(t *testing.T) {
	want := []byte("line one\nline two\n")
	for _, content := range [][]byte{want, []byte("line one\r\nline two\r\n")} {
		if got := normalizeCatalogCheckout(content); !bytes.Equal(got, want) {
			t.Fatalf("normalized content = %q, want %q", got, want)
		}
	}
}

// WO-64@v3: exact official-schema input bytes are provenance, so whitespace drift changes the digest.
func TestServiceAuthorizationCatalogDigestDrift(t *testing.T) {
	input, err := os.ReadFile("testdata/service_authorization_reference.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	driftedPath := filepath.Join(t.TempDir(), "drifted.json")
	if err := os.WriteFile(driftedPath, append(append([]byte(nil), input...), '\n'), 0o644); err != nil {
		t.Fatalf("write drifted fixture: %v", err)
	}
	original := generateCatalog(t, "testdata/service_authorization_reference.json", testCatalogSourceURL, testCatalogRetrievedAt)
	drifted := generateCatalog(t, driftedPath, testCatalogSourceURL, testCatalogRetrievedAt)
	if bytes.Equal(original, drifted) {
		t.Fatal("input drift did not change generated digest")
	}
}

// WO-64@v3: bounded fixtures may omit data but the decoder accepts every official top-level field.
func TestServiceAuthorizationCatalogAcceptsOfficialTopLevelSchema(t *testing.T) {
	input := `{"Name":"ssm","Actions":[{"Name":"GetDocument","Resources":[{"Name":"document"}]}],"ConditionKeys":[],"Operations":[],"Resources":[],"Version":"v1.4"}`
	inputPath := filepath.Join(t.TempDir(), "official-schema.json")
	if err := os.WriteFile(inputPath, []byte(input), 0o644); err != nil {
		t.Fatalf("write official-schema input: %v", err)
	}
	generated := generateCatalog(t, inputPath, testCatalogSourceURL, testCatalogRetrievedAt)
	if !bytes.Contains(generated, []byte(`"ssm:GetDocument": ResourceApplicabilitySupported`)) {
		t.Fatal("official-schema input did not generate the expected action")
	}
}

// WO-64@v3: upstream schema ambiguity and invalid provenance fail closed with field context.
func TestServiceAuthorizationCatalogRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name, input, sourceURL, retrievedAt, want string
	}{
		{name: "unknown field", input: `{"Name":"ssm","Actions":[{"Name":"GetDocument"}],"Version":"v1.4","extra":true}`, sourceURL: testCatalogSourceURL, retrievedAt: testCatalogRetrievedAt, want: "unknown field"},
		{name: "missing service", input: `{"Actions":[{"Name":"GetDocument"}],"Version":"v1.4"}`, sourceURL: testCatalogSourceURL, retrievedAt: testCatalogRetrievedAt, want: "name: required"},
		{name: "missing actions", input: `{"Name":"ssm","Actions":[],"Version":"v1.4"}`, sourceURL: testCatalogSourceURL, retrievedAt: testCatalogRetrievedAt, want: "actions"},
		{name: "missing version", input: `{"Name":"ssm","Actions":[{"Name":"GetDocument"}]}`, sourceURL: testCatalogSourceURL, retrievedAt: testCatalogRetrievedAt, want: "version"},
		{name: "missing action", input: `{"Name":"ssm","Actions":[{}],"Version":"v1.4"}`, sourceURL: testCatalogSourceURL, retrievedAt: testCatalogRetrievedAt, want: "Actions[0].Name"},
		{name: "missing resource", input: `{"Name":"ssm","Actions":[{"Name":"GetDocument","Resources":[{}]}],"Version":"v1.4"}`, sourceURL: testCatalogSourceURL, retrievedAt: testCatalogRetrievedAt, want: "Resources[0].Name"},
		{name: "duplicate normalized action", input: `{"Name":"SSM","Actions":[{"Name":"GetDocument"},{"Name":"getdocument"}],"Version":"v1.4"}`, sourceURL: testCatalogSourceURL, retrievedAt: testCatalogRetrievedAt, want: "duplicate normalized action"},
		{name: "wrong source host", input: `{"Name":"ssm","Actions":[{"Name":"GetDocument"}],"Version":"v1.4"}`, sourceURL: "https://example.com/v1/ssm/ssm.json", retrievedAt: testCatalogRetrievedAt, want: "source-url"},
		{name: "wrong source service", input: `{"Name":"ssm","Actions":[{"Name":"GetDocument"}],"Version":"v1.4"}`, sourceURL: "https://servicereference.us-east-1.amazonaws.com/v1/s3/s3.json", retrievedAt: testCatalogRetrievedAt, want: "source-url"},
		{name: "invalid retrieval time", input: `{"Name":"ssm","Actions":[{"Name":"GetDocument"}],"Version":"v1.4"}`, sourceURL: testCatalogSourceURL, retrievedAt: "today", want: "retrieved-at"},
		{name: "malformed", input: `{`, sourceURL: testCatalogSourceURL, retrievedAt: testCatalogRetrievedAt, want: "decode service reference"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputPath := filepath.Join(t.TempDir(), "input.json")
			if err := os.WriteFile(inputPath, []byte(tt.input), 0o644); err != nil {
				t.Fatalf("write input: %v", err)
			}
			outputPath := filepath.Join(t.TempDir(), "catalog.go")
			command := exec.Command("go", "run", "../../cmd/gencatalog", "-input", inputPath, "-output", outputPath, "-source-url", tt.sourceURL, "-retrieved-at", tt.retrievedAt)
			output, err := command.CombinedOutput()
			if err == nil {
				t.Fatal("generator accepted invalid input")
			}
			if !strings.Contains(string(output), tt.want) {
				t.Fatalf("error = %q, want field context %q", output, tt.want)
			}
		})
	}
}

// WO-64@v3: invoke the offline generator through its user-facing command contract.
func generateCatalog(t *testing.T, inputPath, sourceURL, retrievedAt string) []byte {
	t.Helper()
	outputPath := filepath.Join(t.TempDir(), "catalog.go")
	command := exec.Command("go", "run", "../../cmd/gencatalog", "-input", inputPath, "-output", outputPath, "-source-url", sourceURL, "-retrieved-at", retrievedAt)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generate catalog: %v: %s", err, output)
	}
	generated, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read generated catalog: %v", err)
	}
	return generated
}
