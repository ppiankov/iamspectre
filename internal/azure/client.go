package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

const (
	graphBaseURL = "https://graph.microsoft.com/v1.0"

	// WO-84@v3: bound transport reads independently from diagnostic text retention.
	maxGraphErrorBodyBytes = 64 * 1024
	// WO-84@v3: bound each stored field and the combined Graph-sourced diagnostic.
	maxGraphErrorTextBytes = 4 * 1024
)

// WO-84@v3: redact bearer credentials before retaining any Graph-sourced text.
var bearerCredentialPattern = regexp.MustCompile(`(?i)\bbearer[ \t]+[A-Za-z0-9._~+/=-]+`)

// WO-68@v3: service-principal activity is available only from the Microsoft Graph beta reports surface.
const graphBetaBaseURL = "https://graph.microsoft.com/beta"

// graphScope is the OAuth2 scope for Microsoft Graph API.
const graphScope = "https://graph.microsoft.com/.default"

// WO-68@v3: GraphAPI includes the separate service-principal activity evidence source.
type GraphAPI interface {
	ListUsers(ctx context.Context) ([]User, error)
	ListApplications(ctx context.Context) ([]Application, error)
	ListServicePrincipals(ctx context.Context) ([]ServicePrincipal, error)
	ListServicePrincipalSignInActivities(ctx context.Context) ([]ServicePrincipalSignInActivity, error)
	ListDirectoryRoleAssignments(ctx context.Context) ([]DirectoryRoleAssignment, error)
	ListAuthenticationMethods(ctx context.Context, userID string) ([]AuthenticationMethod, error)
	GetSecurityDefaults(ctx context.Context) (*SecurityDefaultsPolicy, error)
}

// Client wraps the Microsoft Graph API client.
type Client struct {
	Graph    GraphAPI
	TenantID string
}

// WO-84@v3: GraphHTTPError preserves only bounded, diagnostic-safe Graph error fields.
type GraphHTTPError struct {
	StatusCode      int
	Code            string
	Message         string
	RequestID       string
	ClientRequestID string
}

// WO-84@v3: Error omits URLs, bodies, headers, and credentials from operator output.
func (e *GraphHTTPError) Error() string {
	if e == nil {
		return "graph API returned an unknown status"
	}
	base := fmt.Sprintf("graph API returned %d", e.StatusCode)

	parts := make([]string, 0, 4)
	if value := sanitizeGraphErrorText(e.Code); value != "" {
		parts = append(parts, value)
	}
	if value := sanitizeGraphErrorText(e.Message); value != "" {
		parts = append(parts, value)
	}
	if value := sanitizeGraphErrorText(e.RequestID); value != "" {
		parts = append(parts, "request_id="+value)
	}
	if value := sanitizeGraphErrorText(e.ClientRequestID); value != "" {
		parts = append(parts, "client_request_id="+value)
	}
	if len(parts) == 0 {
		return base
	}

	detail := truncateUTF8Bytes(strings.Join(parts, ": "), maxGraphErrorTextBytes)
	return base + ": " + detail
}

// WO-84@v3: graphErrorEnvelope allowlists the only response fields diagnostics retain.
type graphErrorEnvelope struct {
	Error struct {
		Code       string `json:"code"`
		Message    string `json:"message"`
		InnerError struct {
			RequestID       string `json:"request-id"`
			ClientRequestID string `json:"client-request-id"`
		} `json:"innerError"`
	} `json:"error"`
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
	cred        azcore.TokenCredential
	client      *http.Client
	betaBaseURL string // WO-68@v3: injectable only for deterministic fetch-path tests.
}

// WO-68@v3: initialize the production beta endpoint while keeping tests deterministic.
func newGraphClient(cred azcore.TokenCredential) *graphClient {
	return &graphClient{
		cred:        cred,
		client:      &http.Client{Timeout: 30 * time.Second},
		betaBaseURL: graphBetaBaseURL,
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

// WO-68@v3: fetch the authoritative activity report instead of guessing a /servicePrincipals property.
func (g *graphClient) ListServicePrincipalSignInActivities(ctx context.Context) ([]ServicePrincipalSignInActivity, error) {
	url := g.betaBaseURL + "/reports/servicePrincipalSignInActivities?$top=999"
	var all []ServicePrincipalSignInActivity
	if err := paginate(ctx, g, url, &all); err != nil {
		return nil, fmt.Errorf("list service principal sign-in activities: %w", err)
	}
	slog.Debug("Listed Azure AD service principal sign-in activities", "count", len(all))
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
	// WO-5: ignore Close error explicitly to satisfy errcheck (read-only response body).
	defer func() { _ = body.Close() }()

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

		if resp.StatusCode == http.StatusTooManyRequests && attempt < maxRetries-1 {
			// WO-84@v3: decide the retry before decoding and close the discarded body before waiting.
			_ = resp.Body.Close()
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

		// WO-84@v3: terminal transport errors retain only allowlisted, bounded diagnostics.
		graphErr := decodeGraphHTTPError(resp)
		_ = resp.Body.Close()
		return nil, graphErr
	}

	return nil, fmt.Errorf("graph API retry limit exhausted")
}

// WO-84@v3: decodeGraphHTTPError returns the same status-only fallback for unsafe bodies.
func decodeGraphHTTPError(resp *http.Response) *GraphHTTPError {
	result := &GraphHTTPError{StatusCode: resp.StatusCode}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxGraphErrorBodyBytes+1))
	if err != nil || len(body) == 0 || len(body) > maxGraphErrorBodyBytes {
		return result
	}

	var envelope graphErrorEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return result
	}

	result.Code = sanitizeGraphErrorText(envelope.Error.Code)
	result.Message = sanitizeGraphErrorText(envelope.Error.Message)
	result.RequestID = sanitizeGraphErrorText(envelope.Error.InnerError.RequestID)
	result.ClientRequestID = sanitizeGraphErrorText(envelope.Error.InnerError.ClientRequestID)
	if result.RequestID == "" {
		result.RequestID = sanitizeGraphErrorText(resp.Header.Get("request-id"))
	}
	if result.ClientRequestID == "" {
		result.ClientRequestID = sanitizeGraphErrorText(resp.Header.Get("client-request-id"))
	}
	return result
}

// WO-84@v3: sanitizeGraphErrorText removes controls and credentials before truncation.
func sanitizeGraphErrorText(value string) string {
	value = strings.ToValidUTF8(value, "")
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value)
	value = bearerCredentialPattern.ReplaceAllString(value, "Bearer [REDACTED]")
	return truncateUTF8Bytes(value, maxGraphErrorTextBytes)
}

// WO-84@v3: truncateUTF8Bytes enforces byte limits without splitting a code point.
func truncateUTF8Bytes(value string, limit int) string {
	if len(value) <= limit {
		return value
	}

	value = value[:limit]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
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
		// WO-5: ignore Close error explicitly to satisfy errcheck (page body fully decoded).
		_ = body.Close()
		if err != nil {
			return fmt.Errorf("decode response: %w", err)
		}

		*out = append(*out, resp.Value...)
		url = resp.NextLink
	}
	return nil
}
