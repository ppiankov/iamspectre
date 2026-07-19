package aws

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
)

// WO-19@v3: validate fixed-format trust identifiers without accepting wildcard forms.
var (
	organizationIDPattern = regexp.MustCompile(`^o-[a-z0-9]{10,32}$`)
	accountIDPattern      = regexp.MustCompile(`^[0-9]{12}$`)
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

// WO-19@v3: suppress trust findings only when every parsed condition element is understood and bounded.
func (s PolicyStatement) HasRestrictiveTrustCondition() bool {
	operators, ok := s.Condition.(map[string]any)
	if !ok || len(operators) == 0 {
		return false
	}

	found := false
	for operator, rawKeys := range operators {
		keys, ok := rawKeys.(map[string]any)
		if !ok || len(keys) == 0 {
			return false
		}
		for key, rawValues := range keys {
			values, ok := conditionStrings(rawValues)
			if !ok || !isRestrictiveTrustPair(operator, key, values) {
				return false
			}
			found = true
		}
	}
	return found
}

// WO-40: recognize only actions whose IAM glob pattern grants sts:AssumeRole.
func (s PolicyStatement) HasAssumeRoleAction() bool {
	for _, action := range s.Action {
		if matchesActionPattern(action, "sts:AssumeRole") {
			return true
		}
	}
	return false
}

// WO-40: implement IAM's bounded case-insensitive '*' and '?' action pattern semantics.
func matchesActionPattern(pattern, action string) bool {
	pattern = strings.ToLower(pattern)
	action = strings.ToLower(action)

	patternIndex, actionIndex := 0, 0
	starIndex, starMatch := -1, 0
	for actionIndex < len(action) {
		if patternIndex < len(pattern) && (pattern[patternIndex] == '?' || pattern[patternIndex] == action[actionIndex]) {
			patternIndex++
			actionIndex++
			continue
		}
		if patternIndex < len(pattern) && pattern[patternIndex] == '*' {
			starIndex = patternIndex
			patternIndex++
			starMatch = actionIndex
			continue
		}
		if starIndex < 0 {
			return false
		}
		patternIndex = starIndex + 1
		starMatch++
		actionIndex = starMatch
	}
	for patternIndex < len(pattern) && pattern[patternIndex] == '*' {
		patternIndex++
	}
	return patternIndex == len(pattern)
}

// WO-19@v3: accept only the scalar and list shapes IAM documents use for condition values.
func conditionStrings(raw any) ([]string, bool) {
	switch value := raw.(type) {
	case string:
		return []string{value}, true
	case []any:
		values := make([]string, 0, len(value))
		for _, item := range value {
			text, ok := item.(string)
			if !ok {
				return nil, false
			}
			values = append(values, text)
		}
		return values, true
	default:
		return nil, false
	}
}

// WO-19@v3: constrain accepted operators to the trust keys whose values can be proven bounded locally.
func isRestrictiveTrustPair(operator, key string, values []string) bool {
	if len(values) == 0 {
		return false
	}

	var validator func(string) bool
	switch {
	case operator == "StringEquals" && key == "sts:ExternalId":
		validator = isBoundedLiteral
	case operator == "StringEquals" && key == "aws:PrincipalOrgID":
		validator = func(value string) bool { return organizationIDPattern.MatchString(value) }
	case operator == "StringEquals" && key == "aws:SourceAccount":
		validator = func(value string) bool { return accountIDPattern.MatchString(value) }
	case (operator == "ArnEquals" || operator == "ArnLike") && key == "aws:SourceArn":
		validator = isBoundedARN
	case operator == "IpAddress" && key == "aws:SourceIp":
		validator = isBoundedCIDR
	default:
		return false
	}

	for _, value := range values {
		if !validator(value) {
			return false
		}
	}
	return true
}

// WO-19@v3: reject wildcard, variable, and whitespace-bearing trust identifiers.
func isBoundedLiteral(value string) bool {
	return value != "" && !strings.ContainsAny(value, "*?${} \t\r\n")
}

// WO-19@v3: require a syntactically valid ARN with no pattern expansion.
func isBoundedARN(value string) bool {
	return isBoundedLiteral(value) && arn.IsARN(value)
}

// WO-19@v3: reject malformed and universal networks while accepting bounded IPv4 and IPv6 CIDRs.
func isBoundedCIDR(value string) bool {
	if value == "" || strings.TrimSpace(value) != value || strings.Contains(value, "${") {
		return false
	}
	_, network, err := net.ParseCIDR(value)
	if err != nil {
		return false
	}
	ones, _ := network.Mask.Size()
	return ones > 0
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
