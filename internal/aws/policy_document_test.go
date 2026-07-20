package aws

import (
	"encoding/json"
	"net/url"
	"strings"
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

// WO-41@v2: AWS accepts a single Statement object as well as an array.
func TestParsePolicyDocument_SingleStatementObject(t *testing.T) {
	raw := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`

	doc, err := ParsePolicyDocument(url.QueryEscape(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(doc.Statement) != 1 {
		t.Fatalf("expected one statement, got %d", len(doc.Statement))
	}
	if !doc.HasWildcardAction() || !doc.HasWildcardResource() {
		t.Fatal("expected single statement to participate in wildcard detection")
	}
}

// WO-41@v2: object-form trust statements retain their principal and action fields.
func TestParsePolicyDocument_SingleTrustStatementObject(t *testing.T) {
	raw := `{"Statement":{"Sid":"trust","Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}}`
	doc, err := ParsePolicyDocument(url.QueryEscape(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(doc.Statement) != 1 || doc.Statement[0].Sid != "trust" ||
		doc.Statement[0].Principal == nil || !doc.Statement[0].Principal.Wildcard ||
		!doc.Statement[0].HasAssumeRoleAction() {
		t.Fatalf("trust statement was not preserved: %#v", doc.Statement)
	}
}

// WO-41@v2: array normalization preserves statement order and contents.
func TestParsePolicyDocument_StatementArrayOrder(t *testing.T) {
	raw := `{"Statement":[{"Sid":"first","Action":"s3:GetObject"},{"Sid":"second","Action":"s3:PutObject"}]}`
	doc, err := ParsePolicyDocument(url.QueryEscape(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(doc.Statement) != 2 || doc.Statement[0].Sid != "first" || doc.Statement[1].Sid != "second" {
		t.Fatalf("statement order changed: %#v", doc.Statement)
	}
}

// WO-41@v2: shape normalization must preserve legacy empty and null behavior.
func TestParsePolicyDocument_StatementContainerShapes(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want int
	}{
		{name: "absent", raw: `{"Version":"2012-10-17"}`, want: 0},
		{name: "null", raw: `{"Version":"2012-10-17","Statement":null}`, want: 0},
		{name: "empty array", raw: `{"Version":"2012-10-17","Statement":[]}`, want: 0},
		{name: "empty object", raw: `{"Version":"2012-10-17","Statement":{}}`, want: 1},
		{name: "null array element", raw: `{"Version":"2012-10-17","Statement":[null]}`, want: 1},
		{name: "two statements", raw: `{"Version":"2012-10-17","Statement":[{},{}]}`, want: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := ParsePolicyDocument(url.QueryEscape(tt.raw))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(doc.Statement) != tt.want {
				t.Fatalf("statements = %d, want %d", len(doc.Statement), tt.want)
			}
		})
	}
}

// WO-41@v2: malformed Statement containers remain hard parse failures.
func TestParsePolicyDocument_InvalidStatementShapes(t *testing.T) {
	for _, raw := range []string{
		`{"Statement":"bad"}`,
		`{"Statement":42}`,
		`{"Statement":true}`,
		`{"Statement":[42]}`,
		`{"Statement":{"Action":42}}`,
	} {
		if _, err := ParsePolicyDocument(url.QueryEscape(raw)); err == nil {
			t.Fatalf("expected parse error for %s", raw)
		}
	}
	_, err := ParsePolicyDocument(url.QueryEscape(`{"Statement":[{"Effect":42}]}`))
	if err == nil || !strings.Contains(err.Error(), "Effect") {
		t.Fatalf("expected field-qualified array error, got %v", err)
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

// WO-19@v3: pin every accepted condition family and representative fail-open shape.
func TestPolicyStatementHasRestrictiveTrustCondition(t *testing.T) {
	tests := []struct {
		name      string
		condition string
		want      bool
	}{
		{"external id scalar", `{"StringEquals":{"sts:ExternalId":"customer-123"}}`, true},
		{"external id bounded list", `{"StringEquals":{"sts:ExternalId":["one","two"]}}`, true},
		{"organization", `{"StringEquals":{"aws:PrincipalOrgID":"o-1234567890"}}`, true},
		{"organization list", `{"StringEquals":{"aws:PrincipalOrgID":["o-1234567890","o-abcdefghij"]}}`, true},
		{"source account", `{"StringEquals":{"aws:SourceAccount":"123456789012"}}`, true},
		{"source account list", `{"StringEquals":{"aws:SourceAccount":["123456789012","999999999999"]}}`, true},
		{"source arn", `{"ArnEquals":{"aws:SourceArn":"arn:aws:lambda:us-east-1:123456789012:function:worker"}}`, true},
		{"source arn equals list", `{"ArnEquals":{"aws:SourceArn":["arn:aws:lambda:us-east-1:123456789012:function:one","arn:aws:lambda:us-east-1:123456789012:function:two"]}}`, true},
		{"bounded arn like", `{"ArnLike":{"aws:SourceArn":"arn:aws:s3:::named-bucket"}}`, true},
		{"bounded arn like list", `{"ArnLike":{"aws:SourceArn":["arn:aws:s3:::bucket-one","arn:aws:s3:::bucket-two"]}}`, true},
		{"ipv4 cidr", `{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}`, true},
		{"ipv4 cidr list", `{"IpAddress":{"aws:SourceIp":["10.0.0.0/8","192.0.2.0/24"]}}`, true},
		{"ipv6 cidr", `{"IpAddress":{"aws:SourceIp":"2001:db8::/32"}}`, true},
		{"ipv6 cidr list", `{"IpAddress":{"aws:SourceIp":["2001:db8::/32","2001:db8:1::/48"]}}`, true},
		{"absent", `null`, false},
		{"empty condition", `{}`, false},
		{"inverted", `{"StringNotEquals":{"sts:ExternalId":"customer-123"}}`, false},
		{"null", `{"Null":{"sts:ExternalId":"false"}}`, false},
		{"if exists", `{"StringEqualsIfExists":{"sts:ExternalId":"customer-123"}}`, false},
		{"set operator", `{"ForAnyValue:StringEquals":{"sts:ExternalId":"customer-123"}}`, false},
		{"unsupported key", `{"StringEquals":{"aws:username":"alice"}}`, false},
		{"empty value", `{"StringEquals":{"sts:ExternalId":""}}`, false},
		{"whitespace value", `{"StringEquals":{"sts:ExternalId":"customer 123"}}`, false},
		{"wildcard value", `{"StringEquals":{"sts:ExternalId":"customer-*"}}`, false},
		{"variable value", `{"StringEquals":{"sts:ExternalId":"${aws:username}"}}`, false},
		{"mixed broad list", `{"StringEquals":{"sts:ExternalId":["customer-123","*"]}}`, false},
		{"mixed broad arn list", `{"ArnEquals":{"aws:SourceArn":["arn:aws:s3:::named-bucket","arn:aws:s3:::bucket-*"]}}`, false},
		{"mixed universal cidr list", `{"IpAddress":{"aws:SourceIp":["10.0.0.0/8","::/0"]}}`, false},
		{"malformed scalar", `{"StringEquals":{"sts:ExternalId":42}}`, false},
		{"malformed list", `{"StringEquals":{"sts:ExternalId":["customer-123",42]}}`, false},
		{"bad organization", `{"StringEquals":{"aws:PrincipalOrgID":"organization"}}`, false},
		{"bad account", `{"StringEquals":{"aws:SourceAccount":"1234"}}`, false},
		{"wildcard arn", `{"ArnLike":{"aws:SourceArn":"arn:aws:s3:::bucket-*"}}`, false},
		{"invalid arn", `{"ArnEquals":{"aws:SourceArn":"not-an-arn"}}`, false},
		{"universal ipv4", `{"IpAddress":{"aws:SourceIp":"0.0.0.0/0"}}`, false},
		{"universal ipv6", `{"IpAddress":{"aws:SourceIp":"::/0"}}`, false},
		{"invalid cidr", `{"IpAddress":{"aws:SourceIp":"10.0.0.1"}}`, false},
		{"mixed supported unsupported", `{"StringEquals":{"sts:ExternalId":"customer-123"},"Bool":{"aws:SecureTransport":"true"}}`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var condition any
			if err := json.Unmarshal([]byte(tt.condition), &condition); err != nil {
				t.Fatalf("unmarshal condition fixture: %v", err)
			}
			statement := PolicyStatement{Condition: condition}
			if got := statement.HasRestrictiveTrustCondition(); got != tt.want {
				t.Fatalf("HasRestrictiveTrustCondition() = %v, want %v", got, tt.want)
			}
		})
	}
}

// WO-40: match only action patterns that grant the AWS-principal assume-role operation.
func TestPolicyStatementHasAssumeRoleAction(t *testing.T) {
	tests := []struct {
		name    string
		actions StringOrSlice
		want    bool
	}{
		{"exact", StringOrSlice{"sts:AssumeRole"}, true},
		{"case insensitive", StringOrSlice{"STS:assumerole"}, true},
		{"star pattern", StringOrSlice{"sts:Assume*"}, true},
		{"question pattern", StringOrSlice{"sts:AssumeRol?"}, true},
		{"service wildcard", StringOrSlice{"sts:*"}, true},
		{"global wildcard", StringOrSlice{"*"}, true},
		{"matching list", StringOrSlice{"sts:TagSession", "sts:AssumeRole"}, true},
		{"unrelated", StringOrSlice{"s3:GetObject"}, false},
		{"tag session", StringOrSlice{"sts:TagSession"}, false},
		{"saml", StringOrSlice{"sts:AssumeRoleWithSAML"}, false},
		{"web identity", StringOrSlice{"sts:AssumeRoleWithWebIdentity"}, false},
		{"nonmatching list", StringOrSlice{"sts:TagSession", "sts:AssumeRoleWithSAML"}, false},
		{"empty", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statement := PolicyStatement{Action: tt.actions}
			if got := statement.HasAssumeRoleAction(); got != tt.want {
				t.Fatalf("HasAssumeRoleAction() = %v, want %v", got, tt.want)
			}
		})
	}
}

// WO-19@v3: unsupported condition values must not make an otherwise valid policy unparsable.
func TestParsePolicyDocument_PreservesUnsupportedCondition(t *testing.T) {
	raw := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":"sts:AssumeRole","Condition":{"Custom":{"key":{"nested":true}}}}]}`
	doc, err := ParsePolicyDocument(url.QueryEscape(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if doc.Statement[0].HasRestrictiveTrustCondition() {
		t.Fatal("unsupported condition must remain nonconstraining")
	}
}
