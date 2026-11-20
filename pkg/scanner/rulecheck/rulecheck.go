// Package rulecheck compiles custom rules up front, one pattern at a time, so that a broken pattern
// is reported against its rule and pattern instead of stopping the whole scan.
package rulecheck

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"

	"github.com/bearer/bearer/pkg/commands/process/settings"
	"github.com/bearer/bearer/pkg/scanner/ast/query"
	"github.com/bearer/bearer/pkg/scanner/detectors/customrule"
	patternquerybuilder "github.com/bearer/bearer/pkg/scanner/detectors/customrule/patternquery/builder"
	"github.com/bearer/bearer/pkg/scanner/language"
	"github.com/bearer/bearer/pkg/scanner/ruleset"
	"github.com/bearer/bearer/pkg/scanner/variableshape"
	"github.com/bearer/bearer/pkg/structurederrors"
	"github.com/bearer/bearer/pkg/util/set"
)

// Check compiles every rule registered with the collector, for each of its languages, and reports
// problems as structured errors. Rules that fail, and rules that depend on them, are removed from rules so
// that the rest of the scan can run.
func Check(languages []language.Language, rules map[string]*settings.Rule, errorCollector *structurederrors.Collector) {
	if !errorCollector.Enabled() {
		return
	}

	checker := &checker{
		languages:      languages,
		rules:          rules,
		errorCollector: errorCollector,
		invalid:        set.New[string](),
	}

	// Problems that would stop the engine building its rule set for a language come first, as
	// otherwise none of that language's rules could be checked
	checker.checkRuleSetConflicts()
	checker.removeDependents()

	// Patterns are parsed for every rule first, as a rule's variables come from all of its patterns
	// and a rule that fails here cannot be compiled (nor can the rules that use it)
	checker.checkPatternsParse()
	checker.removeDependents()

	checker.checkPatternsCompile()
	checker.removeDependents()

	for id := range checker.invalid {
		delete(rules, id)
	}
}

type checker struct {
	languages      []language.Language
	rules          map[string]*settings.Rule
	errorCollector *structurederrors.Collector
	invalid        set.Set[string]
}

func (checker *checker) checkedRuleIDs() []string {
	var result []string

	for _, id := range slices.Sorted(maps.Keys(checker.rules)) {
		if checker.errorCollector.IsRegisteredRule(id) && !checker.invalid.Has(id) {
			result = append(result, id)
		}
	}

	return result
}

func (checker *checker) ruleLanguages(rule *settings.Rule) []language.Language {
	var result []language.Language

	for _, language := range checker.languages {
		if slices.Contains(rule.Languages, language.ID()) {
			result = append(result, language)
		}
	}

	return result
}

// checkRuleSetConflicts finds rules that the engine would reject when building the rule set for a
// language: rules using the ID of a built-in engine rule, and rules whose sanitizer is not available
// for one of their languages
func (checker *checker) checkRuleSetConflicts() {
	for _, id := range checker.checkedRuleIDs() {
		rule := checker.rules[id]

		if ruleset.IsBuiltinRuleID(id) {
			checker.ruleFailed(
				structurederrors.CodeRuleDuplicateID,
				id,
				"",
				"",
				fmt.Sprintf("rule ID '%s' is reserved for a built-in engine rule", id),
			)
			continue
		}

		sanitizerID := rule.SanitizerRuleID
		if sanitizerID == "" || ruleset.IsBuiltinRuleID(sanitizerID) {
			continue
		}

		sanitizer := checker.rules[sanitizerID]
		for _, language := range checker.ruleLanguages(rule) {
			if sanitizer == nil || !slices.Contains(sanitizer.Languages, language.ID()) {
				checker.ruleFailed(
					structurederrors.CodeSanitizerUnknownRule,
					id,
					language.ID(),
					sanitizerID,
					fmt.Sprintf("sanitizer rule '%s' is not available for language '%s'", sanitizerID, language.ID()),
				)
				break
			}
		}
	}
}

func (checker *checker) checkPatternsParse() {
	for _, id := range checker.checkedRuleIDs() {
		rule := checker.rules[id]

		for _, language := range checker.ruleLanguages(rule) {
			for i, pattern := range rule.Patterns {
				if _, err := patternquerybuilder.Build(language, pattern.Pattern, pattern.Focus); err != nil {
					checker.fail(structurederrors.CodePatternInvalid, id, language, i, pattern.Pattern, err)
				}
			}
		}
	}
}

func (checker *checker) checkPatternsCompile() {
	checkedRuleIDs := set.New[string]()
	checkedRuleIDs.AddAll(checker.checkedRuleIDs())
	if len(checkedRuleIDs) == 0 {
		return
	}

	validRules := make(map[string]*settings.Rule)
	for id, rule := range checker.rules {
		if !checker.invalid.Has(id) {
			validRules[id] = rule
		}
	}

	for _, language := range checker.languages {
		ruleSet, err := ruleset.New(language.ID(), validRules)
		if err != nil {
			checker.languageFailed(language, checkedRuleIDs, err)
			continue
		}

		variableShapeSet, err := variableshape.NewSet(language, ruleSet)
		if err != nil {
			checker.languageFailed(language, checkedRuleIDs, err)
			continue
		}

		for _, rule := range ruleSet.Rules() {
			if !checkedRuleIDs.Has(rule.ID()) {
				continue
			}

			for i, pattern := range rule.Patterns() {
				checker.checkPatternCompile(language, ruleSet, variableShapeSet, rule, i, pattern.Pattern)
			}
		}
	}
}

func (checker *checker) checkPatternCompile(
	language language.Language,
	ruleSet *ruleset.Set,
	variableShapeSet *variableshape.Set,
	rule *ruleset.Rule,
	patternIndex int,
	pattern string,
) {
	querySet := query.NewSet(language.ID(), language.SitterLanguage())
	defer querySet.Close()

	if err := customrule.ValidatePattern(language, ruleSet, variableShapeSet, querySet, rule, patternIndex); err != nil {
		code := structurederrors.CodePatternInvalid

		var patternError *customrule.PatternError
		if errors.As(err, &patternError) {
			err = patternError.Err
			if patternError.IsFilter {
				code = structurederrors.CodeFilterInvalid
			}
		}

		checker.fail(code, rule.ID(), language, patternIndex, pattern, err)
		return
	}

	if err := querySet.Compile(); err != nil {
		checker.fail(structurederrors.CodePatternQueryInvalid, rule.ID(), language, patternIndex, pattern, err)
	}
}

// languageFailed handles a rule set that could not be built for a language, for a reason not caught
// earlier. The checked rules for that language are skipped, as the engine would fail to start with them.
func (checker *checker) languageFailed(language language.Language, checkedRuleIDs set.Set[string], err error) {
	skipped := false

	for _, id := range slices.Sorted(maps.Keys(checkedRuleIDs)) {
		if checker.invalid.Has(id) || !slices.Contains(checker.rules[id].Languages, language.ID()) {
			continue
		}

		checker.ruleFailed(structurederrors.CodeRuleSetInvalid, id, language.ID(), "", err.Error())
		skipped = true
	}

	if !skipped {
		checker.errorCollector.Add(structurederrors.Item{
			Severity: structurederrors.SeverityError,
			Stage:    structurederrors.StageCompile,
			Code:     structurederrors.CodeRuleSetInvalid,
			Message:  err.Error(),
			Language: language.ID(),
		})
	}
}

// ruleFailed marks a rule as invalid for a reason that is not about one of its patterns
func (checker *checker) ruleFailed(code structurederrors.Code, ruleID, languageID, relatedRuleID, message string) {
	checker.invalid.Add(ruleID)

	checker.errorCollector.Add(structurederrors.Item{
		Severity:      structurederrors.SeverityError,
		Stage:         structurederrors.StageCompile,
		Code:          code,
		Message:       message,
		RuleID:        ruleID,
		Language:      languageID,
		RelatedRuleID: relatedRuleID,
		RuleSkipped:   true,
	})
}

// patternPositionPattern matches the position in a pattern parse error from the pattern query builder
var patternPositionPattern = regexp.MustCompile(`error parsing pattern at (\d+):(\d+):`)

func (checker *checker) fail(
	code structurederrors.Code,
	ruleID string,
	language language.Language,
	patternIndex int,
	pattern string,
	err error,
) {
	checker.invalid.Add(ruleID)

	item := structurederrors.Item{
		Severity:     structurederrors.SeverityError,
		Stage:        structurederrors.StageCompile,
		Code:         code,
		Message:      err.Error(),
		RuleID:       ruleID,
		PatternIndex: structurederrors.Index(patternIndex),
		Pattern:      pattern,
		Language:     language.ID(),
		RuleSkipped:  true,
	}

	if match := patternPositionPattern.FindStringSubmatch(err.Error()); match != nil {
		line, _ := strconv.Atoi(match[1])
		column, _ := strconv.Atoi(match[2])
		item.Position = &structurederrors.Position{Line: line, Column: column}
	}

	checker.errorCollector.Add(item)
}

// removeDependents marks as invalid every rule that uses an invalid rule, until there are no more
func (checker *checker) removeDependents() {
	for {
		changed := false

		for _, id := range slices.Sorted(maps.Keys(checker.rules)) {
			if checker.invalid.Has(id) {
				continue
			}

			dependencyID := checker.invalidDependency(id)
			if dependencyID == "" {
				continue
			}

			checker.invalid.Add(id)
			changed = true

			checker.errorCollector.Add(structurederrors.Item{
				Severity:      structurederrors.SeverityError,
				Stage:         structurederrors.StageCompile,
				Code:          structurederrors.CodeRuleDependencyInvalid,
				Message:       fmt.Sprintf("rule depends on rule '%s', which is invalid", dependencyID),
				RuleID:        id,
				RelatedRuleID: dependencyID,
				RuleSkipped:   true,
			})
		}

		if !changed {
			return
		}
	}
}

func (checker *checker) invalidDependency(id string) string {
	rule := checker.rules[id]

	if parentID := checker.errorCollector.ParentRuleID(id); checker.invalid.Has(parentID) {
		return parentID
	}

	for _, dependencyID := range ruleReferences(rule) {
		if checker.invalid.Has(dependencyID) {
			return dependencyID
		}
	}

	return ""
}

func ruleReferences(rule *settings.Rule) []string {
	references := set.New[string]()

	if rule.SanitizerRuleID != "" {
		references.Add(rule.SanitizerRuleID)
	}

	references.AddAll(rule.Trigger.RequiredDetections)

	var addFilters func(filters []settings.PatternFilter)
	addFilters = func(filters []settings.PatternFilter) {
		for _, filter := range filters {
			if filter.Detection != "" {
				references.Add(filter.Detection)
			}

			if filter.Not != nil {
				addFilters([]settings.PatternFilter{*filter.Not})
			}

			addFilters(filter.Either)
			addFilters(filter.Filters)
		}
	}

	for _, pattern := range rule.Patterns {
		addFilters(pattern.Filters)
	}

	result := references.Items()
	slices.Sort(result)
	return result
}
