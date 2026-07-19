package commands

import (
	"strings"
	"testing"
)

// WO-13@v2: pin deterministic region selection for account-global IAM scans.
func TestResolveAWSRegion(t *testing.T) {
	tests := []struct {
		name    string
		regions []string
		want    string
		wantErr bool
	}{
		{name: "empty"},
		{name: "empty entries", regions: []string{"", ""}},
		{name: "one", regions: []string{"us-east-1"}, want: "us-east-1"},
		{name: "duplicate", regions: []string{"us-east-1", "us-east-1"}, want: "us-east-1"},
		{name: "conflict", regions: []string{"us-east-1", "eu-west-1"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveAWSRegion(tt.regions)
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
