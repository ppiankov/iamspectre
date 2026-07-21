package gcp

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	crmv1 "google.golang.org/api/cloudresourcemanager/v1"
	iamv1 "google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
)

// WO-99@v1: exercise SDK pagination through an in-memory transport with no credentials or socket.
func TestIAMClientListServiceAccountsPaginates(t *testing.T) {
	requests := 0
	iamService, _ := newGCPTestServices(t, func(request *http.Request) *http.Response {
		requests++
		if request.Method != http.MethodGet || request.URL.Path != "/v1/projects/test-project/serviceAccounts" {
			t.Fatalf("request = %s %s", request.Method, request.URL.String())
		}

		if requests == 1 {
			if token := request.URL.Query().Get("pageToken"); token != "" {
				t.Fatalf("first page token = %q", token)
			}
			return jsonResponse(http.StatusOK, `{"accounts":[{"name":"projects/test-project/serviceAccounts/one","email":"one@example.com"}],"nextPageToken":"next"}`)
		}
		if token := request.URL.Query().Get("pageToken"); token != "next" {
			t.Fatalf("second page token = %q, want next", token)
		}
		return jsonResponse(http.StatusOK, `{"accounts":[{"name":"projects/test-project/serviceAccounts/two","email":"two@example.com"}]}`)
	})

	accounts, err := (&iamClient{svc: iamService}).ListServiceAccounts(context.Background(), "test-project")
	if err != nil {
		t.Fatalf("list service accounts: %v", err)
	}
	if requests != 2 || len(accounts) != 2 || accounts[0].Email != "one@example.com" || accounts[1].Email != "two@example.com" {
		t.Fatalf("accounts = %#v, requests = %d", accounts, requests)
	}
}

// WO-99@v1: pin the user-managed key filter and decoded key response at the provider boundary.
func TestIAMClientListServiceAccountKeys(t *testing.T) {
	iamService, _ := newGCPTestServices(t, func(request *http.Request) *http.Response {
		if request.Method != http.MethodGet || request.URL.Path != "/v1/projects/test-project/serviceAccounts/one/keys" {
			t.Fatalf("request = %s %s", request.Method, request.URL.String())
		}
		if got := request.URL.Query().Get("keyTypes"); got != "USER_MANAGED" {
			t.Fatalf("keyTypes = %q, want USER_MANAGED", got)
		}
		return jsonResponse(http.StatusOK, `{"keys":[{"name":"projects/test-project/serviceAccounts/one/keys/key-1","keyType":"USER_MANAGED"}]}`)
	})

	keys, err := (&iamClient{svc: iamService}).ListServiceAccountKeys(context.Background(), "projects/test-project/serviceAccounts/one")
	if err != nil {
		t.Fatalf("list service account keys: %v", err)
	}
	if len(keys) != 1 || keys[0].Name != "projects/test-project/serviceAccounts/one/keys/key-1" {
		t.Fatalf("keys = %#v", keys)
	}
}

// WO-99@v1: assert the project IAM policy request contract and decoded bindings.
func TestCRMClientGetIAMPolicy(t *testing.T) {
	_, crmService := newGCPTestServices(t, func(request *http.Request) *http.Response {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/projects/test-project:getIamPolicy" {
			t.Fatalf("request = %s %s", request.Method, request.URL.String())
		}
		return jsonResponse(http.StatusOK, `{"bindings":[{"role":"roles/viewer","members":["user:viewer@example.com"]}]}`)
	})

	policy, err := (&crmClient{svc: crmService}).GetIamPolicy(context.Background(), "test-project")
	if err != nil {
		t.Fatalf("get IAM policy: %v", err)
	}
	if len(policy.Bindings) != 1 || policy.Bindings[0].Role != "roles/viewer" || len(policy.Bindings[0].Members) != 1 {
		t.Fatalf("policy = %#v", policy)
	}
}

// WO-83: pin the authoritative project-number lookup used for managed-agent identity.
func TestCRMClientGetProject(t *testing.T) {
	_, crmService := newGCPTestServices(t, func(request *http.Request) *http.Response {
		if request.Method != http.MethodGet || request.URL.Path != "/v1/projects/test-project" {
			t.Fatalf("request = %s %s", request.Method, request.URL.String())
		}
		return jsonResponse(http.StatusOK, `{"projectId":"test-project","projectNumber":"123456789"}`)
	})

	project, err := (&crmClient{svc: crmService}).GetProject(context.Background(), "test-project")
	if err != nil {
		t.Fatalf("get project: %v", err)
	}
	if project.ProjectNumber != testProjectNumber {
		t.Fatalf("project number = %d, want %d", project.ProjectNumber, testProjectNumber)
	}
}

// WO-99@v1: retain stable adapter context when the provider rejects any request.
func TestGCPClientAdaptersWrapProviderErrors(t *testing.T) {
	iamService, crmService := newGCPTestServices(t, func(*http.Request) *http.Response {
		return jsonResponse(http.StatusForbidden, `{"error":{"code":403,"message":"denied"}}`)
	})

	tests := []struct {
		name       string
		call       func() error
		wantPrefix string
	}{
		{
			name: "service accounts",
			call: func() error {
				_, err := (&iamClient{svc: iamService}).ListServiceAccounts(context.Background(), "test-project")
				return err
			},
			wantPrefix: "list service accounts:",
		},
		{
			name: "service account keys",
			call: func() error {
				_, err := (&iamClient{svc: iamService}).ListServiceAccountKeys(context.Background(), "projects/test-project/serviceAccounts/one")
				return err
			},
			wantPrefix: "list service account keys:",
		},
		{
			name: "project policy",
			call: func() error {
				_, err := (&crmClient{svc: crmService}).GetIamPolicy(context.Background(), "test-project")
				return err
			},
			wantPrefix: "get project IAM policy:",
		},
		{
			name: "project metadata",
			call: func() error {
				_, err := (&crmClient{svc: crmService}).GetProject(context.Background(), "test-project")
				return err
			},
			wantPrefix: "get project metadata:",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.call()
			if err == nil || !strings.HasPrefix(err.Error(), test.wantPrefix) {
				t.Fatalf("error = %v, want prefix %q", err, test.wantPrefix)
			}
		})
	}
}

// WO-99@v1: build both Google SDK services around one deterministic in-memory transport.
func newGCPTestServices(t *testing.T, handle func(*http.Request) *http.Response) (*iamv1.Service, *crmv1.Service) {
	t.Helper()
	client := &http.Client{Transport: gcpRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return handle(request), nil
	})}
	ctx := context.Background()
	iamService, err := iamv1.NewService(ctx, option.WithHTTPClient(client), option.WithoutAuthentication())
	if err != nil {
		t.Fatalf("new IAM service: %v", err)
	}
	crmService, err := crmv1.NewService(ctx, option.WithHTTPClient(client), option.WithoutAuthentication())
	if err != nil {
		t.Fatalf("new Resource Manager service: %v", err)
	}
	return iamService, crmService
}

// WO-99@v1: adapt a function into http.RoundTripper without opening a listener.
type gcpRoundTripFunc func(*http.Request) (*http.Response, error)

// WO-99@v1: route every SDK request to its test-owned response function.
func (f gcpRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

// WO-99@v1: construct the minimal JSON response shape expected by Google SDK decoding.
func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
