package gcp

import (
	"context"
	"fmt"
	"log/slog"

	crmv1 "google.golang.org/api/cloudresourcemanager/v1"
	iamv1 "google.golang.org/api/iam/v1"
)

// IAMAPI defines the GCP IAM operations needed for scanning.
type IAMAPI interface {
	ListServiceAccounts(ctx context.Context, project string) ([]*iamv1.ServiceAccount, error)
	ListServiceAccountKeys(ctx context.Context, serviceAccountName string) ([]*iamv1.ServiceAccountKey, error)
}

// ResourceManagerAPI defines the GCP Resource Manager operations needed.
type ResourceManagerAPI interface {
	GetIamPolicy(ctx context.Context, project string) (*crmv1.Policy, error)
}

// Client wraps GCP API clients.
type Client struct {
	IAM             IAMAPI
	ResourceManager ResourceManagerAPI
	Project         string
}

// NewClient creates a GCP client for the given project.
func NewClient(ctx context.Context, project string) (*Client, error) {
	iamSvc, err := iamv1.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("create IAM service: %w", err)
	}

	crmSvc, err := crmv1.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("create Resource Manager service: %w", err)
	}

	slog.Debug("Initialized GCP client", "project", project)
	return &Client{
		IAM:             &iamClient{svc: iamSvc},
		ResourceManager: &crmClient{svc: crmSvc},
		Project:         project,
	}, nil
}

// NewClientWith creates a client with custom API implementations (for testing).
func NewClientWith(project string, iamAPI IAMAPI, crmAPI ResourceManagerAPI) *Client {
	return &Client{
		IAM:             iamAPI,
		ResourceManager: crmAPI,
		Project:         project,
	}
}

// iamClient implements IAMAPI using the real GCP IAM service.
type iamClient struct {
	svc *iamv1.Service
}

func (c *iamClient) ListServiceAccounts(ctx context.Context, project string) ([]*iamv1.ServiceAccount, error) {
	var accounts []*iamv1.ServiceAccount
	req := c.svc.Projects.ServiceAccounts.List("projects/" + project)
	err := req.Pages(ctx, func(resp *iamv1.ListServiceAccountsResponse) error {
		accounts = append(accounts, resp.Accounts...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list service accounts: %w", err)
	}
	slog.Debug("Listed GCP service accounts", "project", project, "count", len(accounts))
	return accounts, nil
}

func (c *iamClient) ListServiceAccountKeys(ctx context.Context, name string) ([]*iamv1.ServiceAccountKey, error) {
	resp, err := c.svc.Projects.ServiceAccounts.Keys.List(name).KeyTypes("USER_MANAGED").Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("list service account keys: %w", err)
	}
	return resp.Keys, nil
}

// crmClient implements ResourceManagerAPI using the real GCP Resource Manager service.
type crmClient struct {
	svc *crmv1.Service
}

func (c *crmClient) GetIamPolicy(ctx context.Context, project string) (*crmv1.Policy, error) {
	policy, err := c.svc.Projects.GetIamPolicy(project, &crmv1.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("get project IAM policy: %w", err)
	}
	return policy, nil
}
