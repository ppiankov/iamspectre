package aws

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
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
