package azure

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
	users          []User
	usersErr       error
	apps           []Application
	appsErr        error
	sps            []ServicePrincipal
	spsErr         error
	spActivities   []ServicePrincipalSignInActivity
	spActivityErr  error
	roleAssigns    []DirectoryRoleAssignment
	roleAssignsErr error
	authMethods    map[string][]AuthenticationMethod
	authMethodsErr map[string]error
	secDefaults    *SecurityDefaultsPolicy
	secDefaultsErr error
}

func (m *mockGraph) ListUsers(_ context.Context) ([]User, error) {
	return m.users, m.usersErr
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

// WO-68@v3: keep pagination links bound to the deterministic test server.
func serverURL(request *http.Request) string {
	return "http://" + request.Host
}
