// Command gencatalog deterministically compiles a pinned AWS authorization fixture.
// WO-64@v3: generation is an offline supply-chain step, never a scanner runtime dependency.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/format"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// WO-64@v3: restrict provenance to AWS's documented service-reference host.
const serviceReferenceHost = "servicereference.us-east-1.amazonaws.com"

// WO-64@v3: model only the documented official service-reference schema.
type serviceReference struct {
	Name          string            `json:"Name"`
	Actions       []action          `json:"Actions"`
	ConditionKeys []json.RawMessage `json:"ConditionKeys,omitempty"`
	Operations    []json.RawMessage `json:"Operations,omitempty"`
	Resources     []json.RawMessage `json:"Resources,omitempty"`
	Version       string            `json:"Version"`
}

// WO-64@v3: retain action resource evidence and accept documented ancillary fields.
type action struct {
	Name                string          `json:"Name"`
	ActionConditionKeys []string        `json:"ActionConditionKeys,omitempty"`
	Annotations         json.RawMessage `json:"Annotations,omitempty"`
	Resources           []resource      `json:"Resources,omitempty"`
	SupportedBy         json.RawMessage `json:"SupportedBy,omitempty"`
}

// WO-64@v3: resource presence is the only applicability fact published in this schema.
type resource struct {
	Name string `json:"Name"`
}

// WO-64@v3: bind a pinned fixture to its retrieval provenance outside AWS's payload.
type sourceMetadata struct {
	URL         string
	RetrievedAt string
}

// WO-64@v3: normalize source actions into deterministic generated entries.
type catalogEntry struct {
	Name          string
	Applicability string
}

// WO-64@v3: expose deterministic offline generation as an explicit build-time command.
func main() {
	inputPath := flag.String("input", "", "pinned AWS service reference JSON")
	outputPath := flag.String("output", "", "generated Go catalog")
	sourceURL := flag.String("source-url", "", "exact AWS service reference source URL")
	retrievedAt := flag.String("retrieved-at", "", "source retrieval time in RFC3339 form")
	flag.Parse()
	if *inputPath == "" || *outputPath == "" || *sourceURL == "" || *retrievedAt == "" {
		fatalf("-input, -output, -source-url, and -retrieved-at are required")
	}
	input, err := os.ReadFile(*inputPath)
	if err != nil {
		fatalf("read input: %v", err)
	}
	output, err := generate(input, sourceMetadata{URL: *sourceURL, RetrievedAt: *retrievedAt})
	if err != nil {
		fatalf("generate catalog: %v", err)
	}
	if err := os.WriteFile(*outputPath, output, 0o644); err != nil {
		fatalf("write output: %v", err)
	}
}

// WO-64@v3: reject upstream schema drift and ambiguous action records before emitting data.
func generate(input []byte, metadata sourceMetadata) ([]byte, error) {
	var source serviceReference
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&source); err != nil {
		return nil, fmt.Errorf("decode service reference: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return nil, err
	}
	if source.Name == "" {
		return nil, errors.New("name: required")
	}
	if len(source.Actions) == 0 {
		return nil, errors.New("actions: at least one action is required")
	}
	if source.Version == "" {
		return nil, errors.New("version: required")
	}
	if err := validateMetadata(metadata, source.Name); err != nil {
		return nil, err
	}

	seen := make(map[string]string)
	entries := make([]catalogEntry, 0, len(source.Actions))
	for actionIndex, action := range source.Actions {
		field := fmt.Sprintf("Actions[%d]", actionIndex)
		if action.Name == "" {
			return nil, fmt.Errorf("%s.Name: required", field)
		}
		name := strings.ToLower(source.Name) + ":" + action.Name
		normalized := strings.ToLower(name)
		if previous, ok := seen[normalized]; ok {
			return nil, fmt.Errorf("%s.Name: duplicate normalized action %q (first %q)", field, name, previous)
		}
		seen[normalized] = name
		applicability := "ResourceApplicabilityNone"
		if len(action.Resources) > 0 {
			applicability = "ResourceApplicabilitySupported"
		}
		for resourceIndex, resource := range action.Resources {
			if resource.Name == "" {
				return nil, fmt.Errorf("%s.Resources[%d].Name: required", field, resourceIndex)
			}
		}
		entries = append(entries, catalogEntry{Name: name, Applicability: applicability})
	}
	sort.Slice(entries, func(i, j int) bool { return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name) })
	digest := sha256.Sum256(input)
	return render(source, metadata, hex.EncodeToString(digest[:]), entries)
}

// WO-64@v3: accept provenance only from the exact official per-service endpoint.
func validateMetadata(metadata sourceMetadata, service string) error {
	parsed, err := url.Parse(metadata.URL)
	if err != nil || parsed.Scheme != "https" || parsed.Host != serviceReferenceHost {
		return errors.New("source-url: required official AWS service reference HTTPS URL")
	}
	service = strings.ToLower(service)
	wantPath := fmt.Sprintf("/v1/%s/%s.json", service, service)
	if parsed.Path != wantPath || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("source-url: path must be %q", wantPath)
	}
	if _, err := time.Parse(time.RFC3339, metadata.RetrievedAt); err != nil {
		return fmt.Errorf("retrieved-at: %w", err)
	}
	return nil
}

// WO-64@v3: reject concatenated JSON so the hashed fixture has one interpretation.
func requireEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("decode service reference: trailing JSON value")
		}
		return fmt.Errorf("decode service reference trailing data: %w", err)
	}
	return nil
}

// WO-64@v3: sorted entries and explicit metadata make identical inputs byte-reproducible.
func render(source serviceReference, metadata sourceMetadata, digest string, entries []catalogEntry) ([]byte, error) {
	var output bytes.Buffer
	fmt.Fprintln(&output, "// Code generated by cmd/gencatalog; DO NOT EDIT.")
	fmt.Fprintf(&output, "// Source: %s\n", metadata.URL)
	fmt.Fprintf(&output, "// Retrieved: %s\n", metadata.RetrievedAt)
	fmt.Fprintf(&output, "// Schema: AWS Service Reference %s\n", source.Version)
	fmt.Fprintf(&output, "// SHA-256: %s\n\n", digest)
	fmt.Fprintln(&output, "package aws")
	fmt.Fprintln(&output)
	fmt.Fprintln(&output, "// WO-64@v3: expose the pinned evidence digest to catalog consumers.")
	fmt.Fprintf(&output, "const resourceApplicabilityCatalogDigest = %q\n", digest)
	fmt.Fprintln(&output)
	fmt.Fprintln(&output, "// WO-64@v3: resourceApplicabilityCatalog is pinned generated evidence, not runtime inference.")
	fmt.Fprintln(&output, "var resourceApplicabilityCatalog = map[string]ResourceApplicability{")
	for _, entry := range entries {
		fmt.Fprintf(&output, "\t%q: %s,\n", entry.Name, entry.Applicability)
	}
	fmt.Fprintln(&output, "}")
	fmt.Fprintln(&output)
	fmt.Fprintln(&output, "// WO-64@v3: ResourceApplicability reports only what the AWS JSON schema proves.")
	fmt.Fprintln(&output, "type ResourceApplicability string")
	fmt.Fprintln(&output)
	fmt.Fprintln(&output, "const (")
	fmt.Fprintln(&output, "\tResourceApplicabilitySupported ResourceApplicability = \"supported\"")
	fmt.Fprintln(&output, "\tResourceApplicabilityNone      ResourceApplicability = \"none\"")
	fmt.Fprintln(&output, ")")
	formatted, err := format.Source(output.Bytes())
	if err != nil {
		return nil, fmt.Errorf("format generated catalog: %w", err)
	}
	return formatted, nil
}

// WO-64@v3: keep generator failures deterministic and non-recovering.
func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
