package report

import (
	"bytes"
	"testing"
)

// WO-128@v2: source-level coverage renders an explicit empty affected set without a synthetic consequence.
func TestPrintTextCoverageSourceGap(t *testing.T) {
	var output bytes.Buffer
	writer := &errWriter{w: &output}
	printTextCoverage(writer, CoverageManifest{Gaps: []CoverageGap{{
		Capability: "aws_eks_pod_identity_associations",
		Cause:      "access_denied",
		Scope:      "aws-region:us-east-1",
	}}}, false)

	const want = "\nCoverage gaps:\n" +
		"  - aws_eks_pod_identity_associations [aws-region:us-east-1]: access_denied; affected=none; evaluable=0/0\n"
	if writer.err != nil {
		t.Fatalf("print coverage: %v", writer.err)
	}
	if output.String() != want {
		t.Fatalf("coverage output = %q, want %q", output.String(), want)
	}
}
