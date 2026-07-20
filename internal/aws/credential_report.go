package aws

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// credentialReportMaxWait is the maximum number of attempts to wait for credential report generation.
const credentialReportMaxWait = 10

// credentialReportPollInterval is the pause between polling attempts.
const credentialReportPollInterval = 2 * time.Second

// IAMAPI defines the IAM operations used by the scanners.
type IAMAPI interface {
	GenerateCredentialReport(ctx context.Context, params *iam.GenerateCredentialReportInput, optFns ...func(*iam.Options)) (*iam.GenerateCredentialReportOutput, error)
	GetCredentialReport(ctx context.Context, params *iam.GetCredentialReportInput, optFns ...func(*iam.Options)) (*iam.GetCredentialReportOutput, error)
	ListRoles(ctx context.Context, params *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error)
	ListPolicies(ctx context.Context, params *iam.ListPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListPoliciesOutput, error)
	GetPolicyVersion(ctx context.Context, params *iam.GetPolicyVersionInput, optFns ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
}

// CredentialEntry represents a single row from the IAM credential report CSV.
// WO-57@v5: preserve typed credential evidence and its observation boundary.
type CredentialEntry struct {
	User                        string
	ARN                         string
	CredentialReportGeneratedAt *time.Time // WO-61@v2: retain the observation time for credential-derived findings.
	PasswordEnabled             bool
	PasswordLastUsed            *time.Time
	PasswordUseState            PasswordUseState // WO-63: preserve applicable console-use evidence without nil inference.
	MFAActive                   bool
	AccessKey1Active            bool
	AccessKey1LastRotated       *time.Time // WO-57@v5: preserve key age needed to evaluate no-recorded-use evidence.
	AccessKey1LastUsedDate      *time.Time
	AccessKey1UseState          CredentialUseState // WO-57@v5: preserve used, no-recorded-use, or unavailable evidence.
	AccessKey2Active            bool
	AccessKey2LastRotated       *time.Time // WO-57@v5: preserve key age needed to evaluate no-recorded-use evidence.
	AccessKey2LastUsedDate      *time.Time
	AccessKey2UseState          CredentialUseState // WO-57@v5: preserve used, no-recorded-use, or unavailable evidence.
}

// PasswordUseState records how the credential report supports a console-use claim.
type PasswordUseState uint8 // WO-63@v2: keep unavailable and inapplicable password evidence distinct.

// WO-63@v2: keep every typed password evidence state provenance-bound.
const (
	PasswordUseUnknown PasswordUseState = iota
	PasswordUseNoRecordedUse
	PasswordUseNotApplicable
	PasswordUseUsed
)

// CredentialUseState records the evidence carried by an access-key last-used field.
type CredentialUseState uint8 // WO-57@v5: prevent missing evidence from becoming a lifetime-use claim.

// WO-57@v5: keep every typed access-key evidence state provenance-bound.
const (
	CredentialUseUnknown CredentialUseState = iota
	CredentialUseNoRecordedUse
	CredentialUseUsed
)

// FetchCredentialReport generates and retrieves the IAM credential report.
// WO-61@v2: propagate report-generation provenance into every parsed entry.
func FetchCredentialReport(ctx context.Context, client IAMAPI) ([]CredentialEntry, error) {
	// Generate the report
	for i := 0; i < credentialReportMaxWait; i++ {
		out, err := client.GenerateCredentialReport(ctx, &iam.GenerateCredentialReportInput{})
		if err != nil {
			return nil, fmt.Errorf("generate credential report: %w", err)
		}
		if out.State == iamtypes.ReportStateTypeComplete {
			break
		}
		slog.Debug("Credential report generating", "state", out.State, "attempt", i+1)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(credentialReportPollInterval):
		}
	}

	// Retrieve the report
	getOut, err := client.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
	if err != nil {
		return nil, fmt.Errorf("get credential report: %w", err)
	}

	entries, err := parseCredentialReport(getOut.Content)
	if err != nil {
		return nil, err
	}
	if getOut.GeneratedTime != nil {
		for i := range entries {
			generatedAt := getOut.GeneratedTime.UTC()
			entries[i].CredentialReportGeneratedAt = &generatedAt // WO-61@v2: give each entry its own immutable timestamp value.
		}
	}
	return entries, nil
}

// parseCredentialReport parses the CSV content of the credential report.
// WO-57@v5: parse credential rows into explicit evidence states before evaluation.
func parseCredentialReport(content []byte) ([]CredentialEntry, error) {
	reader := csv.NewReader(bytes.NewReader(content))

	// Read header row
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("read credential report header: %w", err)
	}

	// Build column index map
	colIdx := make(map[string]int, len(header))
	for i, h := range header {
		colIdx[h] = i
	}

	// Validate required columns exist
	required := []string{"user", "arn", "password_enabled", "password_last_used", "mfa_active",
		"access_key_1_active", "access_key_1_last_rotated", "access_key_1_last_used_date",
		"access_key_2_active", "access_key_2_last_rotated", "access_key_2_last_used_date"}
	for _, col := range required {
		if _, ok := colIdx[col]; !ok {
			return nil, fmt.Errorf("credential report missing column: %s", col)
		}
	}

	var entries []CredentialEntry
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read credential report row: %w", err)
		}

		// Skip the root account row (<root_account>)
		user := record[colIdx["user"]]
		if user == "<root_account>" {
			continue
		}

		entry := CredentialEntry{User: user, ARN: record[colIdx["arn"]]}
		entry.PasswordEnabled, err = parseCredentialBool("password_enabled", record[colIdx["password_enabled"]])
		if err != nil {
			return nil, fmt.Errorf("parse credential report row for %s: %w", user, err)
		}
		entry.MFAActive, err = parseCredentialBool("mfa_active", record[colIdx["mfa_active"]])
		if err != nil {
			return nil, fmt.Errorf("parse credential report row for %s: %w", user, err)
		}
		entry.AccessKey1Active, err = parseCredentialBool("access_key_1_active", record[colIdx["access_key_1_active"]])
		if err != nil {
			return nil, fmt.Errorf("parse credential report row for %s: %w", user, err)
		}
		entry.AccessKey2Active, err = parseCredentialBool("access_key_2_active", record[colIdx["access_key_2_active"]])
		if err != nil {
			return nil, fmt.Errorf("parse credential report row for %s: %w", user, err)
		}

		entry.PasswordLastUsed, entry.PasswordUseState, err = parsePasswordUse(
			entry.PasswordEnabled,
			record[colIdx["password_last_used"]],
		)
		if err != nil {
			return nil, fmt.Errorf("parse credential report row for %s: password_last_used: %w", user, err)
		}
		entry.AccessKey1LastRotated, err = parseCredentialTimestamp(
			"access_key_1_last_rotated",
			record[colIdx["access_key_1_last_rotated"]],
		)
		if err != nil {
			return nil, fmt.Errorf("parse credential report row for %s: %w", user, err)
		}
		entry.AccessKey1LastUsedDate, entry.AccessKey1UseState, err = parseAccessKeyUse(
			"access_key_1_last_used_date",
			record[colIdx["access_key_1_last_used_date"]],
		)
		if err != nil {
			return nil, fmt.Errorf("parse credential report row for %s: %w", user, err)
		}
		entry.AccessKey2LastRotated, err = parseCredentialTimestamp(
			"access_key_2_last_rotated",
			record[colIdx["access_key_2_last_rotated"]],
		)
		if err != nil {
			return nil, fmt.Errorf("parse credential report row for %s: %w", user, err)
		}
		entry.AccessKey2LastUsedDate, entry.AccessKey2UseState, err = parseAccessKeyUse(
			"access_key_2_last_used_date",
			record[colIdx["access_key_2_last_used_date"]],
		)
		if err != nil {
			return nil, fmt.Errorf("parse credential report row for %s: %w", user, err)
		}

		entries = append(entries, entry)
	}

	slog.Debug("Parsed credential report", "entries", len(entries))
	return entries, nil
}

// WO-57@v5: preserve valid key-age evidence while rejecting corrupt timestamps.
func parseCredentialTimestamp(field, value string) (*time.Time, error) {
	switch value {
	case "", "N/A", "not_supported", "no_information":
		return nil, nil
	}
	timestamp := parseCredentialTime(value)
	if timestamp == nil {
		return nil, fmt.Errorf("%s: invalid timestamp %q", field, value)
	}
	return timestamp, nil
}

// WO-63: credential-report booleans must be exact before they cross finding boundaries.
func parseCredentialBool(field, value string) (bool, error) {
	switch value {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("%s: invalid boolean %q", field, value)
	}
}

// WO-63: parse console-use evidence consistently with console applicability.
func parsePasswordUse(enabled bool, value string) (*time.Time, PasswordUseState, error) {
	switch value {
	case "N/A":
		if enabled {
			return nil, PasswordUseUnknown, fmt.Errorf("password is enabled but value is N/A")
		}
		return nil, PasswordUseNotApplicable, nil
	case "no_information":
		return nil, PasswordUseNoRecordedUse, nil
	case "", "not_supported":
		return nil, PasswordUseUnknown, nil
	}

	lastUsed := parseCredentialTime(value)
	if lastUsed == nil {
		return nil, PasswordUseUnknown, fmt.Errorf("invalid timestamp %q", value)
	}
	return lastUsed, PasswordUseUsed, nil
}

// WO-57@v5: distinguish no-recorded-use evidence from unavailable or corrupt evidence.
func parseAccessKeyUse(field, value string) (*time.Time, CredentialUseState, error) {
	switch value {
	case "N/A":
		return nil, CredentialUseNoRecordedUse, nil
	case "", "not_supported", "no_information":
		return nil, CredentialUseUnknown, nil
	}

	lastUsed := parseCredentialTime(value)
	if lastUsed == nil {
		return nil, CredentialUseUnknown, fmt.Errorf("%s: invalid timestamp %q", field, value)
	}
	return lastUsed, CredentialUseUsed, nil
}

// parseCredentialTime parses a time string from the credential report.
// Returns nil for "N/A", "not_supported", "no_information", or empty values.
func parseCredentialTime(s string) *time.Time {
	if s == "" || s == "N/A" || s == "not_supported" || s == "no_information" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		// Try alternate format used by some reports
		t, err = time.Parse("2006-01-02T15:04:05+00:00", s)
		if err != nil {
			return nil
		}
	}
	return &t
}
