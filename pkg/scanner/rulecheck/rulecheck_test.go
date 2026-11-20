package rulecheck_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bearer/bearer/pkg/commands/process/settings"
	"github.com/bearer/bearer/pkg/languages/javascript"
	"github.com/bearer/bearer/pkg/scanner/language"
	"github.com/bearer/bearer/pkg/scanner/rulecheck"
	"github.com/bearer/bearer/pkg/structurederrors"
)

func newRule(id string, patterns ...settings.RulePattern) *settings.Rule {
	return &settings.Rule{Id: id, Type: "risk", Languages: []string{"javascript"}, Patterns: patterns}
}

func filterOn(variable, detection string) []settings.PatternFilter {
	return []settings.PatternFilter{{Variable: variable, Detection: detection, Scope: settings.NESTED_SCOPE}}
}

func TestCheck(t *testing.T) {
	languages := []language.Language{javascript.Get()}

	errorCollector := structurederrors.New()
	rules := map[string]*settings.Rule{
		"good":       newRule("good", settings.RulePattern{Pattern: "eval($<_>)"}),
		"bad_syntax": newRule("bad_syntax", settings.RulePattern{Pattern: "eval($<_>)"}, settings.RulePattern{Pattern: "foo($<_>"}),
		"bad_filter": newRule("bad_filter", settings.RulePattern{Pattern: "foo($<X>)", Filters: filterOn("Y", "good")}),
		"dependent":  newRule("dependent", settings.RulePattern{Pattern: "bar($<X>)", Filters: filterOn("X", "bad_syntax")}),
		"unchecked":  newRule("unchecked", settings.RulePattern{Pattern: "baz($<_>)"}),
	}
	for id := range rules {
		if id != "unchecked" {
			errorCollector.RegisterRule(id, id+".yml", "")
		}
	}

	rulecheck.Check(languages, rules, errorCollector)

	assert.Contains(t, rules, "good")
	assert.Contains(t, rules, "unchecked")
	assert.NotContains(t, rules, "bad_syntax")
	assert.NotContains(t, rules, "bad_filter")
	assert.NotContains(t, rules, "dependent")

	items := errorCollector.Items()
	require.Len(t, items, 3)

	byRule := make(map[string]structurederrors.Item)
	for _, item := range items {
		byRule[item.RuleID] = item
	}

	assert.Equal(t, structurederrors.CodePatternInvalid, byRule["bad_syntax"].Code)
	assert.Equal(t, structurederrors.Index(1), byRule["bad_syntax"].PatternIndex)
	assert.Equal(t, "javascript", byRule["bad_syntax"].Language)
	assert.Equal(t, "bad_syntax.yml", byRule["bad_syntax"].RuleFile)
	assert.NotNil(t, byRule["bad_syntax"].Position)

	assert.Equal(t, structurederrors.CodeFilterInvalid, byRule["bad_filter"].Code)
	assert.Equal(t, "unknown variable 'Y'", byRule["bad_filter"].Message)

	assert.Equal(t, structurederrors.CodeRuleDependencyInvalid, byRule["dependent"].Code)
	assert.Equal(t, "bad_syntax", byRule["dependent"].RelatedRuleID)
}

func TestCheckRuleSetConflicts(t *testing.T) {
	languages := []language.Language{javascript.Get()}

	otherLanguageSanitizer := newRule("other_language_sanitizer", settings.RulePattern{Pattern: "clean($<_>)"})
	otherLanguageSanitizer.Languages = []string{"ruby"}

	sanitized := newRule("sanitized", settings.RulePattern{Pattern: "eval($<_>)"})
	sanitized.SanitizerRuleID = "other_language_sanitizer"

	errorCollector := structurederrors.New()
	rules := map[string]*settings.Rule{
		"good":                     newRule("good", settings.RulePattern{Pattern: "eval($<_>)"}),
		"string":                   newRule("string", settings.RulePattern{Pattern: "foo($<_>)"}),
		"other_language_sanitizer": otherLanguageSanitizer,
		"sanitized":                sanitized,
	}
	for id := range rules {
		errorCollector.RegisterRule(id, id+".yml", "")
	}

	rulecheck.Check(languages, rules, errorCollector)

	assert.Contains(t, rules, "good")
	assert.NotContains(t, rules, "string")
	assert.NotContains(t, rules, "sanitized")

	items := errorCollector.Items()
	require.Len(t, items, 2)

	byRule := make(map[string]structurederrors.Item)
	for _, item := range items {
		byRule[item.RuleID] = item
	}

	assert.Equal(t, structurederrors.CodeRuleDuplicateID, byRule["string"].Code)
	assert.Equal(t, structurederrors.CodeSanitizerUnknownRule, byRule["sanitized"].Code)
	assert.Equal(t, "other_language_sanitizer", byRule["sanitized"].RelatedRuleID)
	assert.Equal(t, "javascript", byRule["sanitized"].Language)
}

func TestCheckDisabled(t *testing.T) {
	rules := map[string]*settings.Rule{
		"bad": newRule("bad", settings.RulePattern{Pattern: "foo($<_>"}),
	}

	rulecheck.Check([]language.Language{javascript.Get()}, rules, nil)

	assert.Contains(t, rules, "bad")
}
