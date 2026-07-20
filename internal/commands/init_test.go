package commands

import (
	"strings"
	"testing"
)

// WO-44@v2: generated configuration must expose the AWS service-linked role control.
func TestSampleConfigIncludesServiceLinkedRoleOption(t *testing.T) {
	if !strings.Contains(sampleConfig, "include_service_linked_roles: false") {
		t.Fatal("sample config omits include_service_linked_roles")
	}
}
