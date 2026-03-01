package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

const graphBaseURL = "https://graph.microsoft.com/v1.0"

// graphScope is the OAuth2 scope for Microsoft Graph API.
const graphScope = "https://graph.microsoft.com/.default"

// GraphAPI defines the Microsoft Graph operations needed for scanning.
type GraphAPI interface {
	ListUsers(ctx context.Context) ([]User, error)
	ListApplications(ctx context.Context) ([]Application, error)
	ListServicePrincipals(ctx context.Context) ([]ServicePrincipal, error)
	ListDirectoryRoleAssignments(ctx context.Context) ([]DirectoryRoleAssignment, error)
	ListAuthenticationMethods(ctx context.Context, userID string) ([]AuthenticationMethod, error)
	GetSecurityDefaults(ctx context.Context) (*SecurityDefaultsPolicy, error)
}

// Client wraps the Microsoft Graph API client.
type Client struct {
	Graph    GraphAPI
	TenantID string
}

// NewClient creates an Azure client using DefaultAzureCredential.
func NewClient(ctx context.Context, tenantID string) (*Client, error) {
	opts := &azidentity.DefaultAzureCredentialOptions{}
	if tenantID != "" {
		opts.TenantID = tenantID
	}

	cred, err := azidentity.NewDefaultAzureCredential(opts)
	if err != nil {
		return nil, fmt.Errorf("create Azure credential: %w", err)
	}

	if tenantID == "" {
		tenantID = "default"
	}

	slog.Debug("Initialized Azure client", "tenant_id", tenantID)
	return &Client{
		Graph:    newGraphClient(cred),
		TenantID: tenantID,
	}, nil
}

// NewClientWith creates a client with a custom GraphAPI implementation (for testing).
func NewClientWith(tenantID string, graphAPI GraphAPI) *Client {
	return &Client{
		Graph:    graphAPI,
		TenantID: tenantID,
	}
}

// graphClient implements GraphAPI using net/http and azidentity tokens.
type graphClient struct {
	cred   azcore.TokenCredential
	client *http.Client
}

func newGraphClient(cred azcore.TokenCredential) *graphClient {
	return &graphClient{
		cred:   cred,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (g *graphClient) ListUsers(ctx context.Context) ([]User, error) {
	url := graphBaseURL + "/users?$select=id,displayName,userPrincipalName,userType,createdDateTime,signInActivity&$top=999"
	var all []User
	if err := paginate(ctx, g, url, &all); err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	slog.Debug("Listed Azure AD users", "count", len(all))
	return all, nil
}

func (g *graphClient) ListApplications(ctx context.Context) ([]Application, error) {
	url := graphBaseURL + "/applications?$select=id,appId,displayName,signInAudience,passwordCredentials,keyCredentials&$top=999"
	var all []Application
	if err := paginate(ctx, g, url, &all); err != nil {
		return nil, fmt.Errorf("list applications: %w", err)
	}
	slog.Debug("Listed Azure AD applications", "count", len(all))
	return all, nil
}

func (g *graphClient) ListServicePrincipals(ctx context.Context) ([]ServicePrincipal, error) {
	url := graphBaseURL + "/servicePrincipals?$select=id,appId,displayName&$expand=appRoleAssignments&$top=999"
	var all []ServicePrincipal
	if err := paginate(ctx, g, url, &all); err != nil {
		return nil, fmt.Errorf("list service principals: %w", err)
	}
	slog.Debug("Listed Azure AD service principals", "count", len(all))
	return all, nil
}

func (g *graphClient) ListDirectoryRoleAssignments(ctx context.Context) ([]DirectoryRoleAssignment, error) {
	url := graphBaseURL + "/roleManagement/directory/roleAssignments"
	var all []DirectoryRoleAssignment
	if err := paginate(ctx, g, url, &all); err != nil {
		return nil, fmt.Errorf("list directory role assignments: %w", err)
	}
	slog.Debug("Listed directory role assignments", "count", len(all))
	return all, nil
}

func (g *graphClient) ListAuthenticationMethods(ctx context.Context, userID string) ([]AuthenticationMethod, error) {
	url := graphBaseURL + "/users/" + userID + "/authentication/methods"
	var all []AuthenticationMethod
	if err := paginate(ctx, g, url, &all); err != nil {
		return nil, fmt.Errorf("list authentication methods for %s: %w", userID, err)
	}
	return all, nil
}

func (g *graphClient) GetSecurityDefaults(ctx context.Context) (*SecurityDefaultsPolicy, error) {
	url := graphBaseURL + "/policies/identitySecurityDefaultsEnforcementPolicy"
	body, err := g.doRequest(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("get security defaults: %w", err)
	}
	defer body.Close()

	var p SecurityDefaultsPolicy
	if err := json.NewDecoder(body).Decode(&p); err != nil {
		return nil, fmt.Errorf("decode security defaults: %w", err)
	}
	return &p, nil
}

// doRequest performs an authenticated GET request to Microsoft Graph.
func (g *graphClient) doRequest(ctx context.Context, url string) (io.ReadCloser, error) {
	const maxRetries = 3

	for attempt := range maxRetries {
		token, err := g.cred.GetToken(ctx, policy.TokenRequestOptions{
			Scopes: []string{graphScope},
		})
		if err != nil {
			return nil, fmt.Errorf("get token: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token.Token)
		req.Header.Set("Content-Type", "application/json")

		resp, err := g.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("execute request: %w", err)
		}

		if resp.StatusCode == http.StatusOK {
			return resp.Body, nil
		}

		resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests && attempt < maxRetries-1 {
			retryAfter := 5
			if v := resp.Header.Get("Retry-After"); v != "" {
				if parsed, err := strconv.Atoi(v); err == nil {
					retryAfter = parsed
				}
			}
			slog.Warn("Rate limited, retrying", "retry_after_seconds", retryAfter, "attempt", attempt+1)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(retryAfter) * time.Second):
			}
			continue
		}

		return nil, fmt.Errorf("Graph API returned %d for %s", resp.StatusCode, url)
	}

	return nil, fmt.Errorf("max retries exceeded for %s", url)
}

// paginate fetches all pages of a Graph API collection endpoint.
func paginate[T any](ctx context.Context, g *graphClient, url string, out *[]T) error {
	for url != "" {
		body, err := g.doRequest(ctx, url)
		if err != nil {
			return err
		}

		var resp graphResponse[T]
		err = json.NewDecoder(body).Decode(&resp)
		body.Close()
		if err != nil {
			return fmt.Errorf("decode response: %w", err)
		}

		*out = append(*out, resp.Value...)
		url = resp.NextLink
	}
	return nil
}
