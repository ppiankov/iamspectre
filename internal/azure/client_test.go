package azure

import (
	"context"
	"testing"
)

// mockGraph implements GraphAPI for testing.
type mockGraph struct {
	users          []User
	usersErr       error
	apps           []Application
	appsErr        error
	sps            []ServicePrincipal
	spsErr         error
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
