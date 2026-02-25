package aws

import (
	"encoding/json"
	"net/url"
	"testing"
)

func TestParsePolicyDocument_Basic(t *testing.T) {
	raw := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/*"}]}`
	encoded := url.QueryEscape(raw)

	doc, err := ParsePolicyDocument(encoded)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if doc.Version != "2012-10-17" {
		t.Fatalf("expected version 2012-10-17, got %s", doc.Version)
	}
	if len(doc.Statement) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(doc.Statement))
	}
	if doc.Statement[0].Effect != "Allow" {
		t.Fatalf("expected Allow effect, got %s", doc.Statement[0].Effect)
	}
	if !doc.Statement[0].Action.Contains("s3:GetObject") {
		t.Fatal("expected action s3:GetObject")
	}
}

func TestParsePolicyDocument_ActionArray(t *testing.T) {
	raw := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"*"}]}`
	encoded := url.QueryEscape(raw)

	doc, err := ParsePolicyDocument(encoded)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if len(doc.Statement[0].Action) != 2 {
		t.Fatalf("expected 2 actions, got %d", len(doc.Statement[0].Action))
	}
}

func TestParsePolicyDocument_WildcardAction(t *testing.T) {
	raw := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	encoded := url.QueryEscape(raw)

	doc, err := ParsePolicyDocument(encoded)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if !doc.HasWildcardAction() {
		t.Fatal("expected wildcard action")
	}
	if !doc.HasWildcardResource() {
		t.Fatal("expected wildcard resource")
	}
}

func TestParsePolicyDocument_DenyWildcard(t *testing.T) {
	raw := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`
	encoded := url.QueryEscape(raw)

	doc, err := ParsePolicyDocument(encoded)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Deny wildcards should not be flagged
	if doc.HasWildcardAction() {
		t.Fatal("Deny wildcard action should not be flagged")
	}
}

func TestParsePolicyDocument_NoWildcard(t *testing.T) {
	raw := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/*"}]}`
	encoded := url.QueryEscape(raw)

	doc, err := ParsePolicyDocument(encoded)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if doc.HasWildcardAction() {
		t.Fatal("should not have wildcard action")
	}
	if doc.HasWildcardResource() {
		t.Fatal("should not have wildcard resource")
	}
}

func TestParsePolicyDocument_InvalidJSON(t *testing.T) {
	encoded := url.QueryEscape("not json")
	_, err := ParsePolicyDocument(encoded)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestStringOrSlice_SingleString(t *testing.T) {
	var s StringOrSlice
	if err := json.Unmarshal([]byte(`"s3:GetObject"`), &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(s) != 1 || s[0] != "s3:GetObject" {
		t.Fatalf("expected [s3:GetObject], got %v", s)
	}
}

func TestStringOrSlice_Array(t *testing.T) {
	var s StringOrSlice
	if err := json.Unmarshal([]byte(`["s3:Get*","s3:Put*"]`), &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(s) != 2 {
		t.Fatalf("expected 2 items, got %d", len(s))
	}
}

func TestStringOrSlice_Contains(t *testing.T) {
	s := StringOrSlice{"a", "b", "c"}
	if !s.Contains("b") {
		t.Fatal("expected Contains(b) = true")
	}
	if s.Contains("d") {
		t.Fatal("expected Contains(d) = false")
	}
}

func TestPrincipal_Wildcard(t *testing.T) {
	var p Principal
	if err := json.Unmarshal([]byte(`"*"`), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !p.Wildcard {
		t.Fatal("expected wildcard principal")
	}
}

func TestPrincipal_AWSMap(t *testing.T) {
	var p Principal
	data := `{"AWS":"arn:aws:iam::123456789012:root"}`
	if err := json.Unmarshal([]byte(data), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.Wildcard {
		t.Fatal("should not be wildcard")
	}
	if len(p.AWS) != 1 {
		t.Fatalf("expected 1 AWS principal, got %d", len(p.AWS))
	}
	if p.AWS[0] != "arn:aws:iam::123456789012:root" {
		t.Fatalf("unexpected principal: %s", p.AWS[0])
	}
}

func TestPrincipal_ServiceMap(t *testing.T) {
	var p Principal
	data := `{"Service":"ecs.amazonaws.com"}`
	if err := json.Unmarshal([]byte(data), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(p.Service) != 1 || p.Service[0] != "ecs.amazonaws.com" {
		t.Fatalf("expected ecs.amazonaws.com, got %v", p.Service)
	}
}

func TestPrincipal_MultipleAWS(t *testing.T) {
	var p Principal
	data := `{"AWS":["arn:aws:iam::111111111111:root","arn:aws:iam::222222222222:root"]}`
	if err := json.Unmarshal([]byte(data), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(p.AWS) != 2 {
		t.Fatalf("expected 2 AWS principals, got %d", len(p.AWS))
	}
}
