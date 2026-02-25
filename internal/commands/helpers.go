package commands

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"

	"github.com/ppiankov/iamspectre/internal/report"
)

// enhanceError wraps an error with context and suggestions for common cloud issues.
func enhanceError(action string, err error) error {
	msg := err.Error()

	var hint string
	switch {
	case strings.Contains(msg, "NoCredentialProviders"):
		hint = "Configure AWS credentials: set AWS_PROFILE, AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, or run 'aws configure'"
	case strings.Contains(msg, "ExpiredToken"):
		hint = "AWS session token expired. Refresh credentials or run 'aws sso login'"
	case strings.Contains(msg, "AccessDenied") || strings.Contains(msg, "UnauthorizedAccess"):
		hint = "Insufficient permissions. Apply the IAM policy from 'iamspectre init' to your role/user"
	case strings.Contains(msg, "RequestExpired"):
		hint = "Request expired. Check system clock synchronization"
	case strings.Contains(msg, "Throttling"):
		hint = "AWS API rate limit hit. Increase timeout or retry"
	case strings.Contains(msg, "could not find default credentials"):
		hint = "Configure GCP credentials: run 'gcloud auth application-default login' or set GOOGLE_APPLICATION_CREDENTIALS"
	}

	if hint != "" {
		return fmt.Errorf("%s: %w\n  hint: %s", action, err, hint)
	}
	return fmt.Errorf("%s: %w", action, err)
}

// selectReporter creates the appropriate reporter for the given format.
func selectReporter(format, outputFile string) (report.Reporter, error) {
	w := os.Stdout
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return nil, fmt.Errorf("create output file: %w", err)
		}
		w = f
	}

	switch format {
	case "json":
		return &report.JSONReporter{Writer: w}, nil
	case "text":
		return &report.TextReporter{Writer: w}, nil
	case "sarif":
		return &report.SARIFReporter{Writer: w}, nil
	case "spectrehub":
		return &report.SpectreHubReporter{Writer: w}, nil
	default:
		return nil, fmt.Errorf("unsupported format: %s (use text, json, sarif, or spectrehub)", format)
	}
}

// sha256Sum returns the SHA256 hash of a string.
func sha256Sum(input string) []byte {
	h := sha256.Sum256([]byte(input))
	return h[:]
}
