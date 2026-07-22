package commands

import (
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// WO-103@v3: pin flag precedence while preserving account-global config validation.
func TestResolveAWSRegion(t *testing.T) {
	tests := []struct {
		name    string
		flag    string
		regions []string
		want    string
		wantErr bool
	}{
		{name: "empty"},
		{name: "empty entries", regions: []string{"", ""}},
		{name: "one", regions: []string{"us-east-1"}, want: "us-east-1"},
		{name: "duplicate", regions: []string{"us-east-1", "us-east-1"}, want: "us-east-1"},
		{name: "conflict", regions: []string{"us-east-1", "eu-west-1"}, wantErr: true},
		{name: "flag overrides config", flag: "ap-southeast-1", regions: []string{"us-east-1"}, want: "ap-southeast-1"},
		{name: "flag bypasses config conflict", flag: "ap-southeast-1", regions: []string{"us-east-1", "eu-west-1"}, want: "ap-southeast-1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveAWSRegion(tt.flag, tt.regions)
			if tt.wantErr {
				if err == nil || !strings.Contains(err.Error(), "account-global") {
					t.Fatalf("error = %v, want account-global explanation", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("region = %q, want %q", got, tt.want)
			}
		})
	}
}

// WO-103@v3: keep the missing-region guidance bounded without reclassifying unrelated failures.
func TestEnhanceAWSClientError(t *testing.T) {
	missingRegion := errors.New("failed to resolve service endpoint: Invalid Configuration: Missing Region")
	err := enhanceAWSClientError(missingRegion)
	for _, want := range []string{"--region", "AWS_REGION", "config regions"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("missing-region error = %q, want %q", err, want)
		}
	}
	if !errors.Is(err, missingRegion) {
		t.Fatal("missing-region guidance must preserve the underlying error")
	}

	unrelated := errors.New("credential source unavailable")
	err = enhanceAWSClientError(unrelated)
	if strings.Contains(err.Error(), "--region") || !errors.Is(err, unrelated) {
		t.Fatalf("unrelated error was reclassified: %v", err)
	}
}

// WO-103@v3: bind the public region flag to the command-scoped option consumed by runAWS.
func TestRegisterAWSFlagsRegistersRegion(t *testing.T) {
	cmd := &cobra.Command{Use: "aws"}
	flags := &awsScanFlags{}
	registerAWSFlags(cmd, flags)

	if cmd.Flags().Lookup("region") == nil {
		t.Fatal("AWS command does not register --region")
	}
	if err := cmd.Flags().Set("region", "ap-southeast-1"); err != nil {
		t.Fatalf("set --region: %v", err)
	}
	if flags.region != "ap-southeast-1" {
		t.Fatalf("bound region = %q, want ap-southeast-1", flags.region)
	}
}
