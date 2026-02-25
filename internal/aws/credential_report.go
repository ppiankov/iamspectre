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
type CredentialEntry struct {
	User                   string
	ARN                    string
	PasswordEnabled        bool
	PasswordLastUsed       *time.Time
	MFAActive              bool
	AccessKey1Active       bool
	AccessKey1LastUsedDate *time.Time
	AccessKey2Active       bool
	AccessKey2LastUsedDate *time.Time
}

// FetchCredentialReport generates and retrieves the IAM credential report.
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

	return parseCredentialReport(getOut.Content)
}

// parseCredentialReport parses the CSV content of the credential report.
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
		"access_key_1_active", "access_key_1_last_used_date",
		"access_key_2_active", "access_key_2_last_used_date"}
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

		entry := CredentialEntry{
			User:             user,
			ARN:              record[colIdx["arn"]],
			PasswordEnabled:  record[colIdx["password_enabled"]] == "true",
			MFAActive:        record[colIdx["mfa_active"]] == "true",
			AccessKey1Active: record[colIdx["access_key_1_active"]] == "true",
			AccessKey2Active: record[colIdx["access_key_2_active"]] == "true",
		}

		entry.PasswordLastUsed = parseCredentialTime(record[colIdx["password_last_used"]])
		entry.AccessKey1LastUsedDate = parseCredentialTime(record[colIdx["access_key_1_last_used_date"]])
		entry.AccessKey2LastUsedDate = parseCredentialTime(record[colIdx["access_key_2_last_used_date"]])

		entries = append(entries, entry)
	}

	slog.Debug("Parsed credential report", "entries", len(entries))
	return entries, nil
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
