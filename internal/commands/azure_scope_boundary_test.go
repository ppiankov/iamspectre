package commands

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"

	azurescanner "github.com/ppiankov/iamspectre/internal/azure"
)

const microsoftGraphAppID = "00000003-0000-0000-c000-000000000000"

// WO-85@v2: generatedAzureRole models the exact Azure CLI resource-access entry.
type generatedAzureRole struct {
	ID   string `json:"id"`   // WO-85@v2: published Microsoft Graph application-role identifier.
	Type string `json:"type"` // WO-85@v2: generated grants must remain application roles.
}

// WO-85@v2: generatedAzureResourceAccess models the top-level array element Azure CLI accepts.
type generatedAzureResourceAccess struct {
	ResourceAppID string               `json:"resourceAppId"`  // WO-85@v2: bind grants to Microsoft Graph only.
	Roles         []generatedAzureRole `json:"resourceAccess"` // WO-85@v2: retain a structurally testable role list.
}

// WO-85@v2: pin each least-privilege role to its published application identifier.
var azureApplicationRoleNames = map[string]string{
	"df021288-bdef-4463-88db-98f22de89214": "User.Read.All",
	"9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30": "Application.Read.All",
	"b0afded3-3588-46d8-8b3d-9842eff778da": "AuditLog.Read.All",
	"483bed4a-2ad3-4361-a73b-c83ccdbdc53c": "RoleManagement.Read.Directory",
	"38d9df27-64da-44fd-b7c5-a6fbac20248f": "UserAuthenticationMethod.Read.All",
	"246dd0d5-5bd0-4def-940b-0421030a5b68": "Policy.Read.All",
}

// WO-85@v2: fail closed when a production Graph method or generated role lacks a boundary mapping.
func TestAzurePermissionManifestMatchesGraphAPIBoundary(t *testing.T) {
	var manifest []generatedAzureResourceAccess
	if err := json.Unmarshal([]byte(sampleAzureGraphPermissions), &manifest); err != nil {
		t.Fatalf("parse Azure permissions as required-resource-access array: %v", err)
	}
	if len(manifest) != 1 || manifest[0].ResourceAppID != microsoftGraphAppID {
		t.Fatalf("Azure permission resources = %#v, want one Microsoft Graph entry", manifest)
	}

	methodPermissions := map[string][]string{
		"ListUsers":                            {"User.Read.All"},
		"ListUserSignInActivities":             {"AuditLog.Read.All"},
		"ListApplications":                     {"Application.Read.All"},
		"ListServicePrincipals":                {"Application.Read.All"},
		"ListServicePrincipalSignInActivities": {"AuditLog.Read.All"},
		"ListDirectoryRoleAssignments":         {"RoleManagement.Read.Directory"},
		"ListAuthenticationMethods":            {"UserAuthenticationMethod.Read.All"},
		"GetSecurityDefaults":                  {"Policy.Read.All"},
	}

	graphAPI := reflect.TypeOf((*azurescanner.GraphAPI)(nil)).Elem()
	if graphAPI.NumMethod() != len(methodPermissions) {
		t.Fatalf("GraphAPI methods = %d, permission mappings = %d", graphAPI.NumMethod(), len(methodPermissions))
	}
	for index := 0; index < graphAPI.NumMethod(); index++ {
		method := graphAPI.Method(index).Name
		if len(methodPermissions[method]) == 0 {
			t.Fatalf("GraphAPI method %s has no permission mapping", method)
		}
	}

	seenNames := make(map[string]bool, len(manifest[0].Roles))
	for _, role := range manifest[0].Roles {
		name, known := azureApplicationRoleNames[role.ID]
		if !known {
			t.Fatalf("unknown Microsoft Graph application role %q", role.ID)
		}
		if role.Type != "Role" || strings.Contains(name, "Write") || name == "Directory.Read.All" {
			t.Fatalf("unsafe Azure permission %s (%s)", name, role.Type)
		}
		if seenNames[name] {
			t.Fatalf("duplicate Azure permission %s", name)
		}
		seenNames[name] = true
	}

	wantNames := make([]string, 0, len(azureApplicationRoleNames))
	for _, name := range azureApplicationRoleNames {
		wantNames = append(wantNames, name)
	}
	sort.Strings(wantNames)
	for _, name := range wantNames {
		if !seenNames[name] {
			t.Errorf("generated manifest omits %s", name)
		}
		if !permissionHasConsumer(name, methodPermissions) {
			t.Errorf("generated permission %s has no GraphAPI consumer", name)
		}
	}
}

// WO-85@v2: prove every generated role authorizes at least one production Graph operation.
func permissionHasConsumer(permission string, methodPermissions map[string][]string) bool {
	for _, permissions := range methodPermissions {
		for _, candidate := range permissions {
			if candidate == permission {
				return true
			}
		}
	}
	return false
}
