package azure

import "time"

// User represents a Microsoft Graph user.
type User struct {
	ID                string          `json:"id"`
	DisplayName       string          `json:"displayName"`
	UserPrincipalName string          `json:"userPrincipalName"`
	UserType          string          `json:"userType"` // "Member" or "Guest"
	CreatedDateTime   *time.Time      `json:"createdDateTime"`
	SignInActivity    *SignInActivity `json:"signInActivity"`
}

// SignInActivity holds sign-in timestamps from Azure AD (requires P1 license).
type SignInActivity struct {
	LastSignInDateTime               *time.Time `json:"lastSignInDateTime"`
	LastNonInteractiveSignInDateTime *time.Time `json:"lastNonInteractiveSignInDateTime"`
	LastSuccessfulSignInDateTime     *time.Time `json:"lastSuccessfulSignInDateTime"`
}

// Application represents an Azure AD app registration.
type Application struct {
	ID                  string       `json:"id"`
	AppID               string       `json:"appId"`
	DisplayName         string       `json:"displayName"`
	SignInAudience      string       `json:"signInAudience"`
	PasswordCredentials []Credential `json:"passwordCredentials"`
	KeyCredentials      []Credential `json:"keyCredentials"`
}

// Credential represents a secret or certificate credential on an app registration.
type Credential struct {
	KeyID       string     `json:"keyId"`
	DisplayName string     `json:"displayName"`
	EndDateTime *time.Time `json:"endDateTime"`
}

// ServicePrincipal represents an Azure AD service principal.
type ServicePrincipal struct {
	ID                 string              `json:"id"`
	AppID              string              `json:"appId"`
	DisplayName        string              `json:"displayName"`
	SignInActivity     *SignInActivity     `json:"signInActivity"`
	AppRoleAssignments []AppRoleAssignment `json:"appRoleAssignments"`
}

// AppRoleAssignment represents a permission granted to a service principal.
type AppRoleAssignment struct {
	ID                  string `json:"id"`
	AppRoleID           string `json:"appRoleId"`
	PrincipalID         string `json:"principalId"`
	ResourceDisplayName string `json:"resourceDisplayName"`
	ResourceID          string `json:"resourceId"`
}

// DirectoryRoleAssignment represents an active directory role assignment.
type DirectoryRoleAssignment struct {
	ID               string `json:"id"`
	RoleDefinitionID string `json:"roleDefinitionId"`
	PrincipalID      string `json:"principalId"`
}

// AuthenticationMethod represents a registered authentication method for a user.
type AuthenticationMethod struct {
	ID        string `json:"id"`
	ODataType string `json:"@odata.type"`
}

// SecurityDefaultsPolicy represents the tenant security defaults policy.
type SecurityDefaultsPolicy struct {
	IsEnabled bool `json:"isEnabled"`
}

// graphResponse wraps paginated Graph API responses.
type graphResponse[T any] struct {
	Value    []T    `json:"value"`
	NextLink string `json:"@odata.nextLink"`
}
