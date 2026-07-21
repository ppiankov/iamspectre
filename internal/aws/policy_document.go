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

// ConditionBoundednessState records what local policy-condition evidence proves.
// WO-66@v2: unsupported semantics remain distinct from conditions proved not to bound access.
type ConditionBoundednessState string

// WO-66@v2: keep every condition result state provenance-bound.
const (
	ConditionBounded       ConditionBoundednessState = "BOUNDED"       // WO-66@v2: every condition element is supported and bounded.
	ConditionNotBounded    ConditionBoundednessState = "NOT_BOUNDED"   // WO-66@v2: supported values are explicitly broad.
	ConditionIndeterminate ConditionBoundednessState = "INDETERMINATE" // WO-66@v2: local semantics cannot prove either result.
)

// ConditionBoundednessAssessment carries the tri-state result and an operator-facing reason.
// WO-66@v2: policy findings record why a condition did or did not affect breadth severity.
type ConditionBoundednessAssessment struct {
	State  ConditionBoundednessState
	Reason string
}

// ResourceApplicabilityAssessmentState identifies whether the pinned catalog covers every relevant action.
// WO-65@v2: unknown or pattern-based actions cannot neutralize observed resource breadth.
type ResourceApplicabilityAssessmentState string

// WO-65@v2: keep determinate and indeterminate catalog outcomes distinct.
const (
	ResourceApplicabilityDeterminate   ResourceApplicabilityAssessmentState = "DETERMINATE"
	ResourceApplicabilityIndeterminate ResourceApplicabilityAssessmentState = "INDETERMINATE"
)

// ResourceApplicabilityAssessment summarizes catalog evidence for wildcard-resource statements.
// WO-65@v2: AllNone is true only when every exact action has no supported resource type.
type ResourceApplicabilityAssessment struct {
	State   ResourceApplicabilityAssessmentState // WO-65@v2: distinguish catalog proof from uncertainty.
	AllNone bool                                 // WO-65@v2: neutralize only unanimous no-resource evidence.
	Reason  string                               // WO-65@v2: preserve why evidence was or was not conclusive.
}

// WO-105@v3: wildcardRiskLevel orders statement-correlated policy breadth without changing detection.
type wildcardRiskLevel int

const (
	wildcardRiskNone wildcardRiskLevel = iota
	wildcardRiskMedium
	wildcardRiskHigh
	wildcardRiskCritical
)

// WO-105@v3: wildcardRiskAssessment retains the highest proved risk and its evidence rationale.
type wildcardRiskAssessment struct {
	level  wildcardRiskLevel // WO-105@v3: order the proved statement risk.
	reason string            // WO-105@v3: retain the evidence basis for report metadata.
}

// WO-105@v3: assessWildcardRisk never combines action and resource evidence from different statements.
func (d *PolicyDocument) assessWildcardRisk() wildcardRiskAssessment {
	assessment := wildcardRiskAssessment{}
	for _, statement := range d.Statement {
		candidate := statement.assessWildcardRisk()
		if candidate.level > assessment.level {
			assessment = candidate
		}
	}
	return assessment
}

// WO-105@v3: assessWildcardRisk grades only locally observable statement shape and boundedness.
func (s PolicyStatement) assessWildcardRisk() wildcardRiskAssessment {
	if s.Effect != "Allow" {
		return wildcardRiskAssessment{}
	}

	actions := s.AssessActions()
	wildcardAction := actions.State == ActionAssessmentDeterminate && actions.HasWildcard
	wildcardResource := s.Resource.Contains("*")
	if wildcardResource {
		applicability := s.assessResourceApplicability()
		if applicability.State == ResourceApplicabilityDeterminate && applicability.AllNone {
			wildcardResource = false
		}
	}
	if !wildcardAction && !wildcardResource {
		return wildcardRiskAssessment{}
	}

	conditionBounded := s.AssessConditionBoundedness().State == ConditionBounded
	fullAction := s.Action.Contains("*")
	if fullAction && wildcardResource && !conditionBounded {
		return wildcardRiskAssessment{level: wildcardRiskCritical, reason: "full action and wildcard resource without a proved condition bound"}
	}
	if fullAction {
		return wildcardRiskAssessment{level: wildcardRiskHigh, reason: "full action wildcard is resource or condition scoped"}
	}
	if wildcardAction {
		if wildcardResource && !conditionBounded || len(s.Resource) == 0 && !conditionBounded {
			return wildcardRiskAssessment{level: wildcardRiskHigh, reason: "action wildcard lacks a concrete resource or proved condition bound"}
		}
		return wildcardRiskAssessment{level: wildcardRiskMedium, reason: "action wildcard is resource or condition scoped"}
	}
	if actions.State == ActionAssessmentIndeterminate {
		return wildcardRiskAssessment{level: wildcardRiskHigh, reason: "resource wildcard action evidence is indeterminate"}
	}
	if len(actions.SensitiveActions) > 0 {
		return wildcardRiskAssessment{level: wildcardRiskHigh, reason: "resource wildcard includes a sensitive IAM action"}
	}
	return wildcardRiskAssessment{level: wildcardRiskMedium, reason: "resource wildcard is limited to determinate non-sensitive actions"}
}

// AssessConditionBoundedness evaluates exactly the condition families ratified for local analysis.
// WO-66@v2: key presence is never enough to infer a permission boundary.
func (s PolicyStatement) AssessConditionBoundedness() ConditionBoundednessAssessment {
	operators, ok := s.Condition.(map[string]any)
	if !ok || len(operators) == 0 {
		return ConditionBoundednessAssessment{State: ConditionIndeterminate, Reason: "condition absent or malformed"}
	}

	state := ConditionBoundednessState("")
	for operator, rawKeys := range operators {
		keys, ok := rawKeys.(map[string]any)
		if !ok || len(keys) == 0 {
			return ConditionBoundednessAssessment{State: ConditionIndeterminate, Reason: "condition keys are malformed"}
		}
		for key, rawValues := range keys {
			values, ok := conditionStrings(rawValues)
			if !ok {
				return ConditionBoundednessAssessment{State: ConditionIndeterminate, Reason: "condition values are malformed"}
			}
			pairState := assessConditionPair(operator, key, values)
			if pairState == ConditionIndeterminate || (state != "" && state != pairState) {
				return ConditionBoundednessAssessment{State: ConditionIndeterminate, Reason: "condition semantics are mixed or unsupported"}
			}
			state = pairState
		}
	}
	if state == ConditionNotBounded {
		return ConditionBoundednessAssessment{State: state, Reason: "supported condition values are broad"}
	}
	return ConditionBoundednessAssessment{State: state, Reason: "all supported condition values are bounded"}
}

// WO-66@v2: classify only supported operator/key pairs; unknown semantics fail open.
func assessConditionPair(operator, key string, values []string) ConditionBoundednessState {
	if len(values) == 0 {
		return ConditionIndeterminate
	}
	if !isSupportedConditionPair(operator, key) {
		return ConditionIndeterminate
	}

	bounded, broad := 0, 0
	for _, value := range values {
		if strings.Contains(value, "${") {
			return ConditionIndeterminate
		}
		if isBroadConditionValue(value) {
			broad++
			continue
		}
		if !isRestrictiveTrustPair(operator, key, []string{value}) {
			return ConditionIndeterminate
		}
		bounded++
	}
	if bounded > 0 && broad > 0 {
		return ConditionIndeterminate
	}
	if broad > 0 {
		return ConditionNotBounded
	}
	return ConditionBounded
}

// WO-66@v2: keep the supported taxonomy synchronized with the existing trust-condition validators.
func isSupportedConditionPair(operator, key string) bool {
	return (operator == "StringEquals" && (key == "sts:ExternalId" || key == "aws:PrincipalOrgID" || key == "aws:SourceAccount")) ||
		((operator == "ArnEquals" || operator == "ArnLike") && key == "aws:SourceArn") ||
		(operator == "IpAddress" && key == "aws:SourceIp")
}

// WO-66@v2: recognize only explicit wildcard or universal-network values as proved broad.
func isBroadConditionValue(value string) bool {
	return strings.ContainsAny(value, "*?") || value == "0.0.0.0/0" || value == "::/0"
}

// WO-19@v3: suppress trust findings only when every parsed condition element is understood and bounded.
func (s PolicyStatement) HasRestrictiveTrustCondition() bool {
	return s.AssessConditionBoundedness().State == ConditionBounded
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

// AssessConditionBoundedness aggregates condition evidence from wildcard-resource Allow statements.
// WO-66@v2: one unsupported or broad statement prevents a document-wide bounded conclusion.
func (d *PolicyDocument) AssessConditionBoundedness() ConditionBoundednessAssessment {
	found := false
	state := ConditionBoundednessState("")
	for _, statement := range d.Statement {
		if statement.Effect != "Allow" || !statement.Resource.Contains("*") {
			continue
		}
		found = true
		assessment := statement.AssessConditionBoundedness()
		if assessment.State == ConditionIndeterminate {
			return assessment
		}
		if state != "" && state != assessment.State {
			return ConditionBoundednessAssessment{State: ConditionIndeterminate, Reason: "wildcard-resource statements have mixed condition semantics"}
		}
		state = assessment.State
	}
	if !found {
		return ConditionBoundednessAssessment{State: ConditionIndeterminate, Reason: "no wildcard-resource Allow statement"}
	}
	if state == ConditionNotBounded {
		return ConditionBoundednessAssessment{State: state, Reason: "all wildcard-resource conditions are supported and broad"}
	}
	return ConditionBoundednessAssessment{State: state, Reason: "all wildcard-resource statements have supported bounds"}
}

// WO-105@v3: assessResourceApplicability keeps catalog evidence scoped to one Allow statement.
func (s PolicyStatement) assessResourceApplicability() ResourceApplicabilityAssessment {
	if s.Effect != "Allow" || !s.Resource.Contains("*") {
		return ResourceApplicabilityAssessment{State: ResourceApplicabilityIndeterminate, Reason: "no wildcard-resource Allow statement"}
	}
	if len(s.NotResource) > 0 {
		return ResourceApplicabilityAssessment{State: ResourceApplicabilityIndeterminate, Reason: "Resource and NotResource are both present"}
	}
	actionPresent, actionValid := s.actionForm()
	notActionPresent, _ := s.notActionForm()
	if !actionPresent || !actionValid || notActionPresent || len(s.Action) == 0 {
		return ResourceApplicabilityAssessment{State: ResourceApplicabilityIndeterminate, Reason: "action form is unsupported"}
	}

	allNone := true
	for _, action := range s.Action {
		if strings.ContainsAny(action, "*?") || strings.Contains(action, "${") {
			return ResourceApplicabilityAssessment{State: ResourceApplicabilityIndeterminate, Reason: "action requires expansion"}
		}
		applicability, ok := lookupResourceApplicability(action)
		if !ok {
			return ResourceApplicabilityAssessment{State: ResourceApplicabilityIndeterminate, Reason: "action is absent from pinned catalog"}
		}
		switch applicability {
		case ResourceApplicabilityNone:
			// WO-65@v2: continue only on the exact value proving Resource:* is mandatory.
		case ResourceApplicabilitySupported:
			allNone = false
		default:
			return ResourceApplicabilityAssessment{State: ResourceApplicabilityIndeterminate, Reason: "catalog applicability value is invalid"}
		}
	}
	return ResourceApplicabilityAssessment{State: ResourceApplicabilityDeterminate, AllNone: allNone, Reason: "all exact actions are cataloged"}
}

// AssessResourceApplicability checks exact actions on every wildcard-resource Allow statement.
// WO-65@v2: one unsupported action form or catalog miss preserves the finding.
func (d *PolicyDocument) AssessResourceApplicability() ResourceApplicabilityAssessment {
	found := false
	allNone := true
	for _, statement := range d.Statement {
		if statement.Effect != "Allow" || !statement.Resource.Contains("*") {
			continue
		}
		found = true
		assessment := statement.assessResourceApplicability()
		if assessment.State == ResourceApplicabilityIndeterminate {
			return assessment
		}
		if !assessment.AllNone {
			allNone = false
		}
	}
	if !found {
		return ResourceApplicabilityAssessment{State: ResourceApplicabilityIndeterminate, Reason: "no wildcard-resource Allow statement"}
	}
	return ResourceApplicabilityAssessment{State: ResourceApplicabilityDeterminate, AllNone: allNone, Reason: "all exact actions are cataloged"}
}

// WO-65@v2: IAM action matching is ASCII case-insensitive while generated keys retain AWS spelling.
func lookupResourceApplicability(action string) (ResourceApplicability, bool) {
	for catalogAction, applicability := range resourceApplicabilityCatalog {
		if strings.EqualFold(catalogAction, action) {
			return applicability, true
		}
	}
	return "", false
}
