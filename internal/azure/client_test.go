package azure

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

// WO-68@v3: staticTokenCredential is a non-secret test credential.
type staticTokenCredential struct{}

// WO-68@v3: avoid external credentials in the beta report fetch-path test.
func (staticTokenCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "test", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

// WO-68@v3: mockGraph carries service-principal activity separately from principal objects.
type mockGraph struct {
	users           []User
	usersErr        error
	userActivities  []UserSignInActivity // WO-81@v4: protected activity fixtures stay separate from base users.
	userActivityErr error                // WO-81@v4: inject source-wide activity failures without erasing users.
	apps            []Application
	appsErr         error
	sps             []ServicePrincipal
	spsErr          error
	spActivities    []ServicePrincipalSignInActivity
	spActivityErr   error
	roleAssigns     []DirectoryRoleAssignment
	roleAssignsErr  error
	authMethods     map[string][]AuthenticationMethod
	authMethodsErr  map[string]error
	secDefaults     *SecurityDefaultsPolicy
	secDefaultsErr  error
}

func (m *mockGraph) ListUsers(_ context.Context) ([]User, error) {
	return m.users, m.usersErr
}

// WO-81@v4: expose the protected activity source independently from base users.
func (m *mockGraph) ListUserSignInActivities(_ context.Context) ([]UserSignInActivity, error) {
	return m.userActivities, m.userActivityErr
}

func (m *mockGraph) ListApplications(_ context.Context) ([]Application, error) {
	return m.apps, m.appsErr
}

func (m *mockGraph) ListServicePrincipals(_ context.Context) ([]ServicePrincipal, error) {
	return m.sps, m.spsErr
}

// WO-68@v3: expose report evidence independently from service-principal objects.
func (m *mockGraph) ListServicePrincipalSignInActivities(_ context.Context) ([]ServicePrincipalSignInActivity, error) {
	return m.spActivities, m.spActivityErr
}

func (m *mockGraph) ListDirectoryRoleAssignments(_ context.Context) ([]DirectoryRoleAssignment, error) {
	return m.roleAssigns, m.roleAssignsErr
}

func (m *mockGraph) ListAuthenticationMethods(_ context.Context, userID string) ([]AuthenticationMethod, error) {
	if m.authMethodsErr != nil {
		if err, ok := m.authMethodsErr[userID]; ok {
			return nil, err
		}
	}
	if m.authMethods != nil {
		return m.authMethods[userID], nil
	}
	return nil, nil
}

func (m *mockGraph) GetSecurityDefaults(_ context.Context) (*SecurityDefaultsPolicy, error) {
	return m.secDefaults, m.secDefaultsErr
}

func TestNewClientWith(t *testing.T) {
	mock := &mockGraph{}
	client := NewClientWith("test-tenant", mock)

	if client.TenantID != "test-tenant" {
		t.Fatalf("expected tenant_id test-tenant, got %s", client.TenantID)
	}
	if client.Graph == nil {
		t.Fatal("expected non-nil Graph API")
	}
}

func TestNewClientWith_EmptyTenant(t *testing.T) {
	mock := &mockGraph{}
	client := NewClientWith("", mock)

	if client.TenantID != "" {
		t.Fatalf("expected empty tenant_id, got %s", client.TenantID)
	}
}

// WO-68@v3: pin the real beta report route, pagination, and official appId/lastSignInActivity shape.
func TestGraphClient_ListServicePrincipalSignInActivities(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.Header.Get("Authorization") != "Bearer test" {
			t.Fatalf("authorization = %q", request.Header.Get("Authorization"))
		}
		writer.Header().Set("Content-Type", "application/json")
		response := map[string]any{"value": []any{map[string]any{
			"id": "row-1", "appId": "app-1", "lastSignInActivity": map[string]any{"lastSignInDateTime": "2026-01-01T00:00:00Z"},
		}}}
		if requests == 1 {
			if request.URL.Path != "/reports/servicePrincipalSignInActivities" {
				t.Fatalf("path = %q", request.URL.Path)
			}
			response["@odata.nextLink"] = serverURL(request) + "/page-2"
		} else {
			response["value"] = []any{map[string]any{"id": "row-2", "appId": "app-2"}}
		}
		if err := json.NewEncoder(writer).Encode(response); err != nil {
			t.Fatal(err)
		}
	}))
	defer server.Close()

	client := &graphClient{cred: staticTokenCredential{}, client: server.Client(), betaBaseURL: server.URL}
	activities, err := client.ListServicePrincipalSignInActivities(context.Background())
	if err != nil {
		t.Fatalf("ListServicePrincipalSignInActivities: %v", err)
	}
	if requests != 2 || len(activities) != 2 || activities[0].AppID != "app-1" || activities[0].LastSignInActivity == nil {
		t.Fatalf("activities = %#v, requests=%d", activities, requests)
	}
}

// WO-84@v3: Graph authorization diagnostics must survive the public client's wrapping.
func TestGraphClient_ListUserSignInActivitiesPreservesGraphHTTPError(t *testing.T) {
	tests := []struct {
		name string
		code string
	}{
		{name: "missing permission", code: "Authorization_RequestDenied"},
		{name: "premium license required", code: "Authentication_RequestFromNonPremiumTenantOrB2CTenant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := `{"error":{"code":"` + tt.code + `","message":"access denied","innerError":{"request-id":"body-request","client-request-id":"body-client"}}}`
			client := graphClientForResponse(http.StatusForbidden, body, http.Header{
				"Request-Id":        []string{"header-request"},
				"Client-Request-Id": []string{"header-client"},
			})

			_, err := client.ListUserSignInActivities(context.Background())
			var graphErr *GraphHTTPError
			if !errors.As(err, &graphErr) {
				t.Fatalf("ListUserSignInActivities error = %T %v, want *GraphHTTPError", err, err)
			}
			if graphErr.StatusCode != http.StatusForbidden || graphErr.Code != tt.code {
				t.Fatalf("GraphHTTPError = %#v", graphErr)
			}
			if graphErr.RequestID != "body-request" || graphErr.ClientRequestID != "body-client" {
				t.Fatalf("body correlation IDs did not take precedence: %#v", graphErr)
			}
		})
	}
}

// WO-84@v3: invalid Graph bodies must collapse to one safe typed fallback.
func TestGraphClient_ErrorBodyFallbacks(t *testing.T) {
	oversized := strings.Repeat("x", maxGraphErrorBodyBytes+1)
	tests := []struct {
		name string
		body io.ReadCloser
	}{
		{name: "empty", body: io.NopCloser(strings.NewReader(""))},
		{name: "malformed", body: io.NopCloser(strings.NewReader(`{"error":`))},
		{name: "trailing garbage", body: io.NopCloser(strings.NewReader(`{"error":{}} trailing`))},
		{name: "oversized", body: io.NopCloser(strings.NewReader(oversized))},
		{name: "read failure", body: &failingReadCloser{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			closed := &observedReadCloser{ReadCloser: tt.body}
			client := graphClientWithTransport(roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusForbidden,
					Header: http.Header{
						"Request-Id": []string{"must-not-survive"},
					},
					Body: closed,
				}, nil
			}))

			_, err := client.doRequest(context.Background(), "https://graph.microsoft.com/v1.0/users?secret=hidden")
			var graphErr *GraphHTTPError
			if !errors.As(err, &graphErr) {
				t.Fatalf("doRequest error = %T %v, want *GraphHTTPError", err, err)
			}
			if graphErr.StatusCode != http.StatusForbidden || graphErr.Code != "" || graphErr.Message != "" ||
				graphErr.RequestID != "" || graphErr.ClientRequestID != "" {
				t.Fatalf("fallback retained untrusted fields: %#v", graphErr)
			}
			if !closed.closed {
				t.Fatal("non-success body was not closed")
			}
			if strings.Contains(err.Error(), "secret=hidden") || strings.Contains(err.Error(), "must-not-survive") {
				t.Fatalf("fallback leaked request data: %q", err)
			}
		})
	}
}

// WO-84@v3: the body and text limits are byte-exact and preserve valid UTF-8.
func TestGraphClient_ErrorLimits(t *testing.T) {
	base := []byte(`{"error":{"code":"accepted","message":"ok"}}`)
	exact := append(base, bytes.Repeat([]byte(" "), maxGraphErrorBodyBytes-len(base))...)
	client := graphClientForResponse(http.StatusForbidden, string(exact), nil)

	_, err := client.doRequest(context.Background(), "https://graph.microsoft.com/v1.0/users")
	var graphErr *GraphHTTPError
	if !errors.As(err, &graphErr) || graphErr.Code != "accepted" {
		t.Fatalf("exact-limit body error = %T %#v", err, graphErr)
	}

	message := strings.Repeat("é", maxGraphErrorTextBytes)
	body, marshalErr := json.Marshal(map[string]any{"error": map[string]any{
		"code": "unicode", "message": message,
	}})
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	client = graphClientForResponse(http.StatusForbidden, string(body), nil)
	_, err = client.doRequest(context.Background(), "https://graph.microsoft.com/v1.0/users")
	if !errors.As(err, &graphErr) {
		t.Fatalf("unicode error = %T %v", err, err)
	}
	if len(graphErr.Message) != maxGraphErrorTextBytes || !utf8.ValidString(graphErr.Message) {
		t.Fatalf("message bytes=%d valid=%t", len(graphErr.Message), utf8.ValidString(graphErr.Message))
	}
	if len(err.Error()) > maxGraphErrorTextBytes+64 || !utf8.ValidString(err.Error()) {
		t.Fatalf("rendered error bytes=%d valid=%t", len(err.Error()), utf8.ValidString(err.Error()))
	}
}

// WO-84@v3: only sanitized, bounded allowlisted Graph fields may reach diagnostics.
func TestGraphClient_ErrorSanitizesUntrustedValues(t *testing.T) {
	body := `{"error":{"code":"Authorization_RequestDenied","message":"denied Bearer body-secret\u0000","innerError":{"request-id":"body\nBearer request-secret"}}}`
	client := graphClientForResponse(http.StatusForbidden, body, http.Header{
		"Client-Request-Id": []string{"Bearer header-secret\r\n"},
		"Authorization":     []string{"Bearer response-secret"},
		"X-Unrelated":       []string{"https://example.test/?secret=query-secret"},
	})

	_, err := client.doRequest(context.Background(), "https://graph.microsoft.com/v1.0/users?secret=request-secret")
	var graphErr *GraphHTTPError
	if !errors.As(err, &graphErr) {
		t.Fatalf("doRequest error = %T %v", err, err)
	}
	all := graphErr.Code + graphErr.Message + graphErr.RequestID + graphErr.ClientRequestID + err.Error()
	for _, forbidden := range []string{"body-secret", "request-secret", "header-secret", "response-secret", "query-secret", "\x00", "\n", "\r"} {
		if strings.Contains(all, forbidden) {
			t.Fatalf("diagnostics leaked %q: %#v / %q", forbidden, graphErr, err)
		}
	}
}

// WO-84@v3: retry decisions precede decoding and every discarded 429 body is closed.
func TestGraphClient_RetriesAndClosesRateLimitBodies(t *testing.T) {
	var calls int
	var previous *observedReadCloser
	client := graphClientWithTransport(roundTripFunc(func(*http.Request) (*http.Response, error) {
		if previous != nil && !previous.closed {
			t.Fatalf("request %d started before the prior body closed", calls+1)
		}
		calls++
		previous = &observedReadCloser{ReadCloser: io.NopCloser(strings.NewReader(
			`{"error":{"code":"TooManyRequests","message":"retry later"}}`,
		))}
		return &http.Response{
			StatusCode: http.StatusTooManyRequests,
			Header:     http.Header{"Retry-After": []string{"0"}},
			Body:       previous,
		}, nil
	}))

	_, err := client.doRequest(context.Background(), "https://graph.microsoft.com/v1.0/users")
	var graphErr *GraphHTTPError
	if !errors.As(err, &graphErr) || graphErr.Code != "TooManyRequests" {
		t.Fatalf("terminal retry error = %T %#v", err, graphErr)
	}
	if calls != 3 || previous == nil || !previous.closed {
		t.Fatalf("calls=%d final body closed=%t", calls, previous != nil && previous.closed)
	}
}

// WO-84@v3: successful response body ownership remains with the caller.
func TestGraphClient_SuccessBodyOwnership(t *testing.T) {
	body := &observedReadCloser{ReadCloser: io.NopCloser(strings.NewReader(`{"value":[]}`))}
	client := graphClientWithTransport(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
	}))

	returned, err := client.doRequest(context.Background(), "https://graph.microsoft.com/v1.0/users")
	if err != nil {
		t.Fatal(err)
	}
	if body.closed {
		t.Fatal("successful body was closed before returning to caller")
	}
	if err := returned.Close(); err != nil {
		t.Fatal(err)
	}
	if !body.closed {
		t.Fatal("caller close did not close successful body")
	}
}

// WO-100@v1: pin every stable Graph list route, query, pagination step, and decoded row count.
func TestGraphClientListMethods(t *testing.T) {
	tests := []struct {
		name  string
		path  string
		query map[string]string
		call  func(*graphClient) (int, error)
	}{
		{
			name: "users",
			path: "/v1.0/users",
			query: map[string]string{
				"$select": "id,displayName,userPrincipalName,userType,createdDateTime",
				"$top":    "999",
			},
			call: func(client *graphClient) (int, error) {
				items, err := client.ListUsers(context.Background())
				return len(items), err
			},
		},
		{
			name: "user sign-in activity",
			path: "/v1.0/users",
			query: map[string]string{
				"$select": "id,signInActivity",
				"$top":    "500",
			},
			call: func(client *graphClient) (int, error) {
				items, err := client.ListUserSignInActivities(context.Background())
				return len(items), err
			},
		},
		{
			name: "applications",
			path: "/v1.0/applications",
			query: map[string]string{
				"$select": "id,appId,displayName,signInAudience,passwordCredentials,keyCredentials",
				"$top":    "999",
			},
			call: func(client *graphClient) (int, error) {
				items, err := client.ListApplications(context.Background())
				return len(items), err
			},
		},
		{
			name: "service principals",
			path: "/v1.0/servicePrincipals",
			query: map[string]string{
				"$select": "id,appId,displayName",
				"$expand": "appRoleAssignments",
				"$top":    "999",
			},
			call: func(client *graphClient) (int, error) {
				items, err := client.ListServicePrincipals(context.Background())
				return len(items), err
			},
		},
		{
			name:  "directory role assignments",
			path:  "/v1.0/roleManagement/directory/roleAssignments",
			query: map[string]string{},
			call: func(client *graphClient) (int, error) {
				items, err := client.ListDirectoryRoleAssignments(context.Background())
				return len(items), err
			},
		},
		{
			name:  "authentication methods",
			path:  "/v1.0/users/user-id/authentication/methods",
			query: map[string]string{},
			call: func(client *graphClient) (int, error) {
				items, err := client.ListAuthenticationMethods(context.Background(), "user-id")
				return len(items), err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requests := 0
			client := graphClientWithTransport(roundTripFunc(func(request *http.Request) (*http.Response, error) {
				requests++
				if request.Header.Get("Authorization") != "Bearer test" {
					t.Fatalf("authorization = %q", request.Header.Get("Authorization"))
				}
				if requests == 1 {
					if request.URL.Path != test.path {
						t.Fatalf("path = %q, want %q", request.URL.Path, test.path)
					}
					for key, want := range test.query {
						if got := request.URL.Query().Get(key); got != want {
							t.Fatalf("query %s = %q, want %q", key, got, want)
						}
					}
					return graphJSONResponse(http.StatusOK, `{"value":[{"id":"one"}],"@odata.nextLink":"https://graph.microsoft.com/v1.0/next"}`), nil
				}
				if request.URL.Path != "/v1.0/next" {
					t.Fatalf("next path = %q", request.URL.Path)
				}
				return graphJSONResponse(http.StatusOK, `{"value":[{"id":"two"}]}`), nil
			}))

			count, err := test.call(client)
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if count != 2 || requests != 2 {
				t.Fatalf("count = %d, requests = %d", count, requests)
			}
		})
	}
}

// WO-100@v1: keep each public Graph method's context while preserving typed provider details.
func TestGraphClientListMethodsWrapGraphErrors(t *testing.T) {
	tests := []struct {
		name       string
		wantPrefix string
		call       func(*graphClient) error
	}{
		{
			name: "user sign-in activity", wantPrefix: "list user sign-in activities:",
			call: func(client *graphClient) error {
				_, err := client.ListUserSignInActivities(context.Background())
				return err
			},
		},
		{
			name: "applications", wantPrefix: "list applications:",
			call: func(client *graphClient) error { _, err := client.ListApplications(context.Background()); return err },
		},
		{
			name: "service principals", wantPrefix: "list service principals:",
			call: func(client *graphClient) error {
				_, err := client.ListServicePrincipals(context.Background())
				return err
			},
		},
		{
			name: "directory role assignments", wantPrefix: "list directory role assignments:",
			call: func(client *graphClient) error {
				_, err := client.ListDirectoryRoleAssignments(context.Background())
				return err
			},
		},
		{
			name: "authentication methods", wantPrefix: "list authentication methods for user-id:",
			call: func(client *graphClient) error {
				_, err := client.ListAuthenticationMethods(context.Background(), "user-id")
				return err
			},
		},
		{
			name: "security defaults", wantPrefix: "get security defaults:",
			call: func(client *graphClient) error {
				_, err := client.GetSecurityDefaults(context.Background())
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := graphClientForResponse(http.StatusForbidden, `{"error":{"code":"Authorization_RequestDenied","message":"denied"}}`, nil)
			err := test.call(client)
			if err == nil || !strings.HasPrefix(err.Error(), test.wantPrefix) {
				t.Fatalf("error = %v, want prefix %q", err, test.wantPrefix)
			}
			var graphErr *GraphHTTPError
			if !errors.As(err, &graphErr) || graphErr.Code != "Authorization_RequestDenied" {
				t.Fatalf("typed Graph error = %#v", graphErr)
			}
		})
	}
}

// WO-100@v1: cover security-default decoding and the production Graph client defaults without credentials.
func TestGraphClientSecurityDefaultsAndDefaults(t *testing.T) {
	client := graphClientWithTransport(roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != "/v1.0/policies/identitySecurityDefaultsEnforcementPolicy" {
			t.Fatalf("path = %q", request.URL.Path)
		}
		return graphJSONResponse(http.StatusOK, `{"isEnabled":true}`), nil
	}))
	policy, err := client.GetSecurityDefaults(context.Background())
	if err != nil {
		t.Fatalf("get security defaults: %v", err)
	}
	if policy == nil || !policy.IsEnabled {
		t.Fatalf("policy = %#v", policy)
	}

	malformed := graphClientForResponse(http.StatusOK, `{`, nil)
	if _, err := malformed.GetSecurityDefaults(context.Background()); err == nil || !strings.HasPrefix(err.Error(), "decode security defaults:") {
		t.Fatalf("decode error = %v", err)
	}

	productionDefaults := newGraphClient(staticTokenCredential{})
	if productionDefaults.client == nil || productionDefaults.client.Timeout != 30*time.Second || productionDefaults.betaBaseURL != graphBetaBaseURL {
		t.Fatalf("production defaults = %#v", productionDefaults)
	}
}

// WO-100@v1: build a minimal Graph response for deterministic transport tests.
func graphJSONResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

// WO-84@v3: roundTripFunc keeps transport edge cases deterministic and network-free.
type roundTripFunc func(*http.Request) (*http.Response, error)

// WO-84@v3: keep request transport behavior injectable for bounded Graph error tests.
func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

// WO-84@v3: observedReadCloser proves response body ownership on every status path.
type observedReadCloser struct {
	io.ReadCloser
	closed bool
}

// WO-84@v3: record closure so retry and terminal response ownership stays provable.
func (r *observedReadCloser) Close() error {
	r.closed = true
	return r.ReadCloser.Close()
}

// WO-84@v3: failingReadCloser exercises the deterministic transport read fallback.
type failingReadCloser struct{}

// WO-84@v3: force a deterministic body-read failure without exposing response bytes.
func (*failingReadCloser) Read([]byte) (int, error) { return 0, errors.New("read failed") }

// WO-84@v3: make the synthetic read failure independently closeable.
func (*failingReadCloser) Close() error { return nil }

// WO-84@v3: build the smallest Graph client around a deterministic synthetic response.
func graphClientForResponse(status int, body string, header http.Header) *graphClient {
	return graphClientWithTransport(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: status,
			Header:     header,
			Body:       io.NopCloser(strings.NewReader(body)),
		}, nil
	}))
}

// WO-84@v3: transport injection avoids widening production configuration for error tests.
func graphClientWithTransport(transport http.RoundTripper) *graphClient {
	return &graphClient{
		cred:   staticTokenCredential{},
		client: &http.Client{Transport: transport},
	}
}

// WO-68@v3: keep pagination links bound to the deterministic test server.
func serverURL(request *http.Request) string {
	return "http://" + request.Host
}
