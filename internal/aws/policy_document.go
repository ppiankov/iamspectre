package aws

import (
	"bytes"
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
// WO-41@v2: accept both AWS-defined Statement container shapes.
type PolicyDocument struct {
	Version   string           `json:"Version"`
	Statement PolicyStatements `json:"Statement"`
}

// PolicyStatements accepts both container shapes allowed by AWS policy syntax.
// WO-45: preserve policy-analysis coverage across accepted shapes and visible failures.
// WO-41@v2: normalize a single statement object without changing downstream iteration.
type PolicyStatements []PolicyStatement

// UnmarshalJSON preserves the legacy array/null contract and adds object-form support.
// WO-41@v2: reject scalar containers while delegating statement fields to encoding/json.
func (s *PolicyStatements) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if bytes.Equal(trimmed, []byte("null")) {
		*s = nil
		return nil
	}
	if len(trimmed) == 0 {
		return fmt.Errorf("unmarshal policy statements: empty JSON value")
	}

	if trimmed[0] == '[' {
		var statements []PolicyStatement
		if err := json.Unmarshal(trimmed, &statements); err != nil {
			return fmt.Errorf("unmarshal policy statement array: %w", err)
		}
		*s = statements
		return nil
	}

	if trimmed[0] != '{' {
		return fmt.Errorf("unmarshal policy statements: expected object or array")
	}
	var statement PolicyStatement
	if err := json.Unmarshal(trimmed, &statement); err != nil {
		return fmt.Errorf("unmarshal policy statements: %w", err)
	}
	*s = PolicyStatements{statement}
	return nil
}

// PolicyStatement represents a single statement in a policy document.
// WO-21@v3: preserve complementary action and resource forms with explicit action-shape evidence.
type PolicyStatement struct {
	Sid         string        `json:"Sid,omitempty"`
	Effect      string        `json:"Effect"`
	Action      StringOrSlice `json:"Action,omitempty"`
	NotAction   StringOrSlice `json:"NotAction,omitempty"` // WO-21@v3: complementary action form
	Resource    StringOrSlice `json:"Resource,omitempty"`
	NotResource StringOrSlice `json:"NotResource,omitempty"` // WO-21@v3: preserve resource complement separately
	Principal   *Principal    `json:"Principal,omitempty"`
	Condition   any           `json:"Condition,omitempty"`

	actionPresent    bool          // WO-21@v3: distinguish absent from unsupported parsed shapes
	actionValid      bool          // WO-21@v3: retain parsed shape validity
	actionParsed     StringOrSlice // WO-21@v3: detect mutation of the exported field after parsing
	notActionPresent bool          // WO-21@v3: distinguish absent from unsupported parsed shapes
	notActionValid   bool          // WO-21@v3: retain parsed shape validity
	notActionParsed  StringOrSlice // WO-21@v3: detect mutation of the exported field after parsing
}

// WO-21@v3: retain unsupported action shapes so callers can distinguish uncertainty from absence.
func (s *PolicyStatement) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		*s = PolicyStatement{}
		return nil
	}

	var raw struct {
		Sid         string          `json:"Sid,omitempty"`
		Effect      string          `json:"Effect"`
		Action      json.RawMessage `json:"Action"`
		NotAction   json.RawMessage `json:"NotAction"`
		Resource    StringOrSlice   `json:"Resource,omitempty"`
		NotResource StringOrSlice   `json:"NotResource,omitempty"`
		Principal   *Principal      `json:"Principal,omitempty"`
		Condition   any             `json:"Condition,omitempty"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	*s = PolicyStatement{
		Sid:         raw.Sid,
		Effect:      raw.Effect,
		Resource:    raw.Resource,
		NotResource: raw.NotResource,
		Principal:   raw.Principal,
		Condition:   raw.Condition,
	}
	s.Action, s.actionPresent, s.actionValid = parseActionField(raw.Action)
	s.NotAction, s.notActionPresent, s.notActionValid = parseActionField(raw.NotAction)
	s.actionParsed = cloneStrings(s.Action)
	s.notActionParsed = cloneStrings(s.NotAction)
	return nil
}

// WO-21@v3: malformed and null action values are evidence for an indeterminate assessment.
func parseActionField(raw json.RawMessage) (StringOrSlice, bool, bool) {
	if len(raw) == 0 {
		return nil, false, false
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, true, false
	}

	var actions StringOrSlice
	if err := json.Unmarshal(raw, &actions); err != nil {
		return nil, true, false
	}
	return actions, true, true
}

// ActionAssessmentState identifies whether local policy evidence supports a conclusive action result.
// WO-21@v3: make unsupported IAM action forms explicit instead of collapsing them into a boolean.
type ActionAssessmentState string

// WO-21@v3: expose the two exhaustive outcomes of local action analysis.
const (
	ActionAssessmentDeterminate   ActionAssessmentState = "DETERMINATE"
	ActionAssessmentIndeterminate ActionAssessmentState = "INDETERMINATE"
)

// ActionAssessment reports wildcard syntax and the ratified sensitive IAM actions a statement may grant.
// WO-21@v3: keep the finite sensitive-action proof separate from full IAM authorization semantics.
type ActionAssessment struct {
	State            ActionAssessmentState // WO-21@v3: explicit local proof state
	HasWildcard      bool                  // WO-21@v3: determinate Action glob evidence
	SensitiveActions []string              // WO-21@v3: matched subset of the ratified fixed list
}

// WO-21@v3: this fixed list is the complete sensitive-action taxonomy ratified by the IAM v2 design.
var sensitiveIAMActions = []string{
	"iam:AttachRolePolicy",
	"iam:AttachUserPolicy",
	"iam:CreatePolicyVersion",
	"iam:PassRole",
	"iam:PutRolePolicy",
	"iam:PutUserPolicy",
	"iam:SetDefaultPolicyVersion",
	"iam:UpdateAssumeRolePolicy",
}

// AssessActions evaluates only the locally provable action semantics of this statement.
// WO-21@v3: NotAction remains indeterminate because a complete AWS action catalog is not bundled.
func (s PolicyStatement) AssessActions() ActionAssessment {
	if s.Effect != "Allow" {
		return ActionAssessment{State: ActionAssessmentDeterminate}
	}

	actionPresent, actionValid := s.actionForm()
	notActionPresent, notActionValid := s.notActionForm()
	if actionPresent == notActionPresent || !actionValid || !notActionValid {
		return ActionAssessment{State: ActionAssessmentIndeterminate}
	}

	patterns := s.Action
	state := ActionAssessmentDeterminate
	if notActionPresent {
		patterns = s.NotAction
		state = ActionAssessmentIndeterminate
	}
	if containsPolicyVariable(patterns) {
		return ActionAssessment{State: ActionAssessmentIndeterminate}
	}

	assessment := ActionAssessment{State: state}
	if actionPresent {
		for _, pattern := range patterns {
			if strings.ContainsAny(pattern, "*?") {
				assessment.HasWildcard = true
				break
			}
		}
	}
	for _, action := range sensitiveIAMActions {
		matched := matchesAnyActionPattern(patterns, action)
		if (actionPresent && matched) || (notActionPresent && !matched) {
			assessment.SensitiveActions = append(assessment.SensitiveActions, action)
		}
	}
	return assessment
}

// WO-21@v3: preserve useful behavior for programmatically constructed statements and parsed presence metadata.
func (s PolicyStatement) actionForm() (bool, bool) {
	if !equalStrings(s.Action, s.actionParsed) {
		return len(s.Action) > 0, true
	}
	if s.actionPresent {
		return true, s.actionValid
	}
	return len(s.Action) > 0, true
}

// WO-21@v3: preserve useful behavior for programmatically constructed statements and parsed presence metadata.
func (s PolicyStatement) notActionForm() (bool, bool) {
	if !equalStrings(s.NotAction, s.notActionParsed) {
		return len(s.NotAction) > 0, true
	}
	if s.notActionPresent {
		return true, s.notActionValid
	}
	return len(s.NotAction) > 0, true
}

// WO-21@v3: snapshot parsed action fields so later exported-field mutations take precedence.
func cloneStrings(values StringOrSlice) StringOrSlice {
	if values == nil {
		return nil
	}
	return append(StringOrSlice(nil), values...)
}

// WO-21@v3: preserve the nil-versus-empty distinction used by parsed action presence metadata.
func equalStrings(left, right StringOrSlice) bool {
	if (left == nil) != (right == nil) || len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// WO-21@v3: policy variables require runtime substitution and cannot be guessed statically.
func containsPolicyVariable(patterns StringOrSlice) bool {
	for _, pattern := range patterns {
		if strings.Contains(pattern, "${") {
			return true
		}
	}
	return false
}

// WO-21@v3: Action arrays are a union of case-insensitive IAM glob patterns.
func matchesAnyActionPattern(patterns StringOrSlice, action string) bool {
	for _, pattern := range patterns {
		if matchesActionPattern(pattern, action) {
			return true
		}
	}
	return false
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
// WO-21@v3: constrain case folding to ASCII, as required for AWS action names.
func matchesActionPattern(pattern, action string) bool {
	pattern = asciiLower(pattern)
	action = asciiLower(action)

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

// WO-21@v3: avoid locale or Unicode folding in the IAM action matcher.
func asciiLower(value string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, value)
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

// HasWildcardAction checks if any determinate Allow statement contains an Action glob.
// WO-21@v3: recognize '*' and '?' without treating indeterminate forms as findings.
func (d *PolicyDocument) HasWildcardAction() bool {
	for _, stmt := range d.Statement {
		assessment := stmt.AssessActions()
		if assessment.State == ActionAssessmentDeterminate && assessment.HasWildcard {
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
