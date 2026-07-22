package aws

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// WO-22@v3: centralize the reviewed AWS client boundary for the internal production tree.
// WO-120@v3: admit the read-only EKS client required by the bounded Pod Identity source.
var allowedAWSServices = map[string]bool{
	"accessanalyzer": true,
	"eks":            true,
	"iam":            true,
	"organizations":  true,
	"sts":            true,
}

// WO-22@v3: fail closed when production AWS code imports an unchartered service client.
func TestAWSScopeBoundary(t *testing.T) {
	var files []string
	err := filepath.WalkDir("..", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("find production packages: %v", err)
	}
	for _, path := range files {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			imp, ok := node.(*ast.ImportSpec)
			if !ok {
				return true
			}
			value, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("unquote import: %v", err)
			}
			const prefix = "github.com/aws/aws-sdk-go-v2/service/"
			if strings.HasPrefix(value, prefix) && !allowedAWSServices[strings.Split(strings.TrimPrefix(value, prefix), "/")[0]] {
				t.Errorf("%s imports AWS service outside IAM scope: %s", path, value)
			}
			return true
		})
	}
}

// WO-22@v3: mutation proof keeps forbidden AWS services outside the allow-list.
func TestAWSScopeBoundaryRejectsForbiddenService(t *testing.T) {
	if allowedAWSServices["s3"] {
		t.Fatal("service/s3 must remain outside the core allow-list")
	}
}
