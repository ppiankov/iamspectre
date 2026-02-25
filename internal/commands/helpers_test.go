package commands

import (
	"errors"
	"strings"
	"testing"
)

func TestEnhanceError_NoCredentials(t *testing.T) {
	err := enhanceError("test", errors.New("NoCredentialProviders: no valid providers"))
	if !strings.Contains(err.Error(), "hint:") {
		t.Fatal("expected hint for NoCredentialProviders")
	}
	if !strings.Contains(err.Error(), "AWS_PROFILE") {
		t.Fatal("expected AWS_PROFILE suggestion")
	}
}

func TestEnhanceError_ExpiredToken(t *testing.T) {
	err := enhanceError("test", errors.New("ExpiredToken: token expired"))
	if !strings.Contains(err.Error(), "hint:") {
		t.Fatal("expected hint for ExpiredToken")
	}
}

func TestEnhanceError_AccessDenied(t *testing.T) {
	err := enhanceError("test", errors.New("AccessDenied: not authorized"))
	if !strings.Contains(err.Error(), "iamspectre init") {
		t.Fatal("expected iamspectre init suggestion")
	}
}

func TestEnhanceError_GCPCredentials(t *testing.T) {
	err := enhanceError("test", errors.New("could not find default credentials"))
	if !strings.Contains(err.Error(), "gcloud auth") {
		t.Fatal("expected gcloud auth suggestion")
	}
}

func TestEnhanceError_NoHint(t *testing.T) {
	err := enhanceError("test action", errors.New("some random error"))
	if strings.Contains(err.Error(), "hint:") {
		t.Fatal("expected no hint for unknown error")
	}
	if !strings.Contains(err.Error(), "test action") {
		t.Fatal("expected action in error message")
	}
}

func TestSelectReporter_ValidFormats(t *testing.T) {
	formats := []string{"text", "json", "sarif", "spectrehub"}
	for _, f := range formats {
		t.Run(f, func(t *testing.T) {
			r, err := selectReporter(f, "")
			if err != nil {
				t.Fatalf("unexpected error for format %s: %v", f, err)
			}
			if r == nil {
				t.Fatalf("expected non-nil reporter for format %s", f)
			}
		})
	}
}

func TestSelectReporter_InvalidFormat(t *testing.T) {
	_, err := selectReporter("csv", "")
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Fatal("expected unsupported format message")
	}
}

func TestSha256Sum(t *testing.T) {
	result := sha256Sum("test")
	if len(result) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(result))
	}
	// Same input should produce same hash
	result2 := sha256Sum("test")
	for i := range result {
		if result[i] != result2[i] {
			t.Fatal("expected deterministic hash")
		}
	}
}

func TestComputeTargetHash(t *testing.T) {
	hash := computeTargetHash("production")
	if !strings.HasPrefix(hash, "sha256:") {
		t.Fatalf("expected sha256: prefix, got %s", hash)
	}
	if len(hash) < 20 {
		t.Fatal("hash too short")
	}
}
