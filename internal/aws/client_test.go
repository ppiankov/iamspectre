package aws

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type mockSTS struct {
	accountID string
	err       error
}

func (m *mockSTS) GetCallerIdentity(_ context.Context, _ *sts.GetCallerIdentityInput, _ ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &sts.GetCallerIdentityOutput{
		Account: awssdk.String(m.accountID),
	}, nil
}

func TestGetAccountID(t *testing.T) {
	client := NewClientWithSTS(awssdk.Config{}, &mockSTS{accountID: "123456789012"})

	accountID, err := client.GetAccountID(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if accountID != "123456789012" {
		t.Fatalf("expected 123456789012, got %s", accountID)
	}
}

func TestGetAccountID_Error(t *testing.T) {
	client := NewClientWithSTS(awssdk.Config{}, &mockSTS{err: context.DeadlineExceeded})

	_, err := client.GetAccountID(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestNewClientWithSTS(t *testing.T) {
	cfg := awssdk.Config{Region: "us-east-1"}
	client := NewClientWithSTS(cfg, &mockSTS{})

	got := client.Config()
	if got.Region != "us-east-1" {
		t.Fatalf("expected region us-east-1, got %s", got.Region)
	}
}

// WO-13@v2: pin profile and region option construction without SDK network calls.
func TestLoadOptions(t *testing.T) {
	tests := []struct {
		name        string
		profile     string
		region      string
		wantOptions int
	}{
		{name: "SDK defaults"},
		{name: "profile", profile: "production", wantOptions: 1},
		{name: "region", region: "us-east-1", wantOptions: 1},
		{name: "both", profile: "production", region: "us-east-1", wantOptions: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := loadOptions(tt.profile, tt.region)
			if len(opts) != tt.wantOptions {
				t.Fatalf("option count = %d, want %d", len(opts), tt.wantOptions)
			}
			var loaded struct {
				region  string
				profile string
			}
			for _, option := range opts {
				var loadOptions awsconfig.LoadOptions
				if err := option(&loadOptions); err != nil {
					t.Fatalf("apply option: %v", err)
				}
				if loadOptions.Region != "" {
					loaded.region = loadOptions.Region
				}
				if loadOptions.SharedConfigProfile != "" {
					loaded.profile = loadOptions.SharedConfigProfile
				}
			}
			if loaded.region != tt.region || loaded.profile != tt.profile {
				t.Fatalf("loaded = %#v, want region %q profile %q", loaded, tt.region, tt.profile)
			}
		})
	}
}
