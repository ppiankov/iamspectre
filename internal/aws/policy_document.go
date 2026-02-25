package aws

import (
	"encoding/json"
	"fmt"
	"net/url"
)

// PolicyDocument represents an AWS IAM policy document.
type PolicyDocument struct {
	Version   string            `json:"Version"`
	Statement []PolicyStatement `json:"Statement"`
}

// PolicyStatement represents a single statement in a policy document.
type PolicyStatement struct {
	Sid       string        `json:"Sid,omitempty"`
	Effect    string        `json:"Effect"`
	Action    StringOrSlice `json:"Action"`
	Resource  StringOrSlice `json:"Resource"`
	Principal *Principal    `json:"Principal,omitempty"`
	Condition any           `json:"Condition,omitempty"`
}

// Principal represents the Principal field in a policy statement.
// It can be "*" (wildcard), or a map of principal types to values.
type Principal struct {
	Wildcard  bool
	AWS       StringOrSlice
	Service   StringOrSlice
	Federated StringOrSlice
}

// UnmarshalJSON implements custom unmarshaling for Principal.
func (p *Principal) UnmarshalJSON(data []byte) error {
	// Try wildcard string first: "Principal": "*"
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		if s == "*" {
			p.Wildcard = true
		}
		return nil
	}

	// Try map form: "Principal": {"AWS": "arn:...", "Service": "..."}
	var m map[string]StringOrSlice
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("unmarshal principal: %w", err)
	}

	p.AWS = m["AWS"]
	p.Service = m["Service"]
	p.Federated = m["Federated"]
	return nil
}

// StringOrSlice handles AWS policy fields that can be a single string or an array.
type StringOrSlice []string

// UnmarshalJSON implements custom unmarshaling for StringOrSlice.
func (s *StringOrSlice) UnmarshalJSON(data []byte) error {
	// Try single string first
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*s = StringOrSlice{single}
		return nil
	}

	// Try array
	var arr []string
	if err := json.Unmarshal(data, &arr); err != nil {
		return fmt.Errorf("unmarshal string or slice: %w", err)
	}
	*s = StringOrSlice(arr)
	return nil
}

// Contains checks if the slice contains a specific string.
func (s StringOrSlice) Contains(val string) bool {
	for _, v := range s {
		if v == val {
			return true
		}
	}
	return false
}

// ParsePolicyDocument decodes a URL-encoded policy document JSON string.
func ParsePolicyDocument(encoded string) (*PolicyDocument, error) {
	decoded, err := url.QueryUnescape(encoded)
	if err != nil {
		return nil, fmt.Errorf("url decode policy document: %w", err)
	}

	var doc PolicyDocument
	if err := json.Unmarshal([]byte(decoded), &doc); err != nil {
		return nil, fmt.Errorf("parse policy document JSON: %w", err)
	}
	return &doc, nil
}

// HasWildcardAction checks if any Allow statement has Action "*".
func (d *PolicyDocument) HasWildcardAction() bool {
	for _, stmt := range d.Statement {
		if stmt.Effect == "Allow" && stmt.Action.Contains("*") {
			return true
		}
	}
	return false
}

// HasWildcardResource checks if any Allow statement has Resource "*".
func (d *PolicyDocument) HasWildcardResource() bool {
	for _, stmt := range d.Statement {
		if stmt.Effect == "Allow" && stmt.Resource.Contains("*") {
			return true
		}
	}
	return false
}
