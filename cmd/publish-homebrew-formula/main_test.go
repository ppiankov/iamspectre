package main

import (
	"encoding/base64"
	"testing"
)

// WO-141: the tap credential must travel to git via GIT_CONFIG_* environment
// variables, never on the process argv. gitAuthEnv is the single place that
// carries it; assert its shape so a regression back to a `-c http.extraheader=`
// argv override (visible in /proc/<pid>/cmdline and ps) is caught.
func TestGitAuthEnvKeepsCredentialOffArgv(t *testing.T) {
	header := "AUTHORIZATION: basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:secret"))
	env := gitAuthEnv(header)

	for _, want := range []string{
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=http.extraheader",
		"GIT_CONFIG_VALUE_0=" + header,
	} {
		if !containsString(env, want) {
			t.Errorf("gitAuthEnv() missing %q; got %v", want, env)
		}
	}
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
