package release

import (
	"strings"
	"testing"
)

func testChecksums() map[string]string {
	return map[string]string{
		"iamspectre_1.2.3_darwin_arm64.tar.gz": "aaaa000000000000000000000000000000000000000000000000000000aaaa",
		"iamspectre_1.2.3_darwin_amd64.tar.gz": "bbbb000000000000000000000000000000000000000000000000000000bbbb",
		"iamspectre_1.2.3_linux_arm64.tar.gz":  "cccc000000000000000000000000000000000000000000000000000000cccc",
		"iamspectre_1.2.3_linux_amd64.tar.gz":  "dddd000000000000000000000000000000000000000000000000000000dddd",
		"iamspectre_1.2.3_windows_amd64.zip":   "eeee000000000000000000000000000000000000000000000000000000eeee",
	}
}

func testFormulaInput() FormulaInput {
	return FormulaInput{
		ProjectName: "iamspectre",
		Version:     "1.2.3",
		Homepage:    "https://github.com/ppiankov/iamspectre",
		Description: "Cross-cloud IAM auditor",
		License:     "MIT",
		RepoOwner:   "ppiankov",
		Checksums:   testChecksums(),
	}
}

// WO-96: the rendered Formula must keep the explicit-version, install, and
// test contract the deprecated `brews` publisher used to guarantee, across
// all four macOS/Linux amd64/arm64 archives.
func TestRenderFormula(t *testing.T) {
	got, err := RenderFormula(testFormulaInput())
	if err != nil {
		t.Fatalf("RenderFormula: %v", err)
	}

	want := `class Iamspectre < Formula
  desc "Cross-cloud IAM auditor"
  homepage "https://github.com/ppiankov/iamspectre"
  version "1.2.3"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/ppiankov/iamspectre/releases/download/v1.2.3/iamspectre_1.2.3_darwin_arm64.tar.gz"
      sha256 "aaaa000000000000000000000000000000000000000000000000000000aaaa"
    end
    on_intel do
      url "https://github.com/ppiankov/iamspectre/releases/download/v1.2.3/iamspectre_1.2.3_darwin_amd64.tar.gz"
      sha256 "bbbb000000000000000000000000000000000000000000000000000000bbbb"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/ppiankov/iamspectre/releases/download/v1.2.3/iamspectre_1.2.3_linux_arm64.tar.gz"
      sha256 "cccc000000000000000000000000000000000000000000000000000000cccc"
    end
    on_intel do
      url "https://github.com/ppiankov/iamspectre/releases/download/v1.2.3/iamspectre_1.2.3_linux_amd64.tar.gz"
      sha256 "dddd000000000000000000000000000000000000000000000000000000dddd"
    end
  end

  def install
    bin.install "iamspectre"
  end

  test do
    system "#{bin}/iamspectre", "version"
  end
end
`
	if got != want {
		t.Fatalf("RenderFormula mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestRenderFormulaMissingChecksum(t *testing.T) {
	in := testFormulaInput()
	delete(in.Checksums, "iamspectre_1.2.3_linux_arm64.tar.gz")

	_, err := RenderFormula(in)
	if err == nil {
		t.Fatal("expected error for missing linux/arm64 checksum, got nil")
	}
	if !strings.Contains(err.Error(), "iamspectre_1.2.3_linux_arm64.tar.gz") {
		t.Fatalf("error = %q, want it to name the missing archive", err.Error())
	}
}

func TestParseChecksums(t *testing.T) {
	input := "aaaa  iamspectre_1.2.3_darwin_arm64.tar.gz\n" +
		"bbbb  iamspectre_1.2.3_darwin_amd64.tar.gz\n" +
		"\n"

	got, err := ParseChecksums(input)
	if err != nil {
		t.Fatalf("ParseChecksums: %v", err)
	}
	want := map[string]string{
		"iamspectre_1.2.3_darwin_arm64.tar.gz": "aaaa",
		"iamspectre_1.2.3_darwin_amd64.tar.gz": "bbbb",
	}
	if len(got) != len(want) {
		t.Fatalf("ParseChecksums returned %d entries, want %d", len(got), len(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("ParseChecksums[%q] = %q, want %q", k, got[k], v)
		}
	}
}

func TestParseChecksumsMalformedLine(t *testing.T) {
	_, err := ParseChecksums("not-a-valid-line-with-three fields here\n")
	if err == nil {
		t.Fatal("expected error for malformed checksums line, got nil")
	}
}
