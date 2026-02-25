package aws

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// STSAPI defines the STS operations used by the client.
type STSAPI interface {
	GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// Client wraps the AWS SDK configuration for creating service clients.
type Client struct {
	cfg    aws.Config
	stsAPI STSAPI
}

// NewClient creates a new AWS client using the specified profile.
func NewClient(ctx context.Context, profile string) (*Client, error) {
	var opts []func(*awsconfig.LoadOptions) error

	if profile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(profile))
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}

	return &Client{
		cfg:    cfg,
		stsAPI: sts.NewFromConfig(cfg),
	}, nil
}

// NewClientWithSTS creates a client with a custom STS implementation (for testing).
func NewClientWithSTS(cfg aws.Config, stsAPI STSAPI) *Client {
	return &Client{cfg: cfg, stsAPI: stsAPI}
}

// Config returns the underlying AWS config.
func (c *Client) Config() aws.Config {
	return c.cfg
}

// GetAccountID returns the AWS account ID for the current credentials.
func (c *Client) GetAccountID(ctx context.Context) (string, error) {
	out, err := c.stsAPI.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("get caller identity: %w", err)
	}

	accountID := ""
	if out.Account != nil {
		accountID = *out.Account
	}

	slog.Debug("Resolved AWS account", "account_id", accountID)
	return accountID, nil
}
