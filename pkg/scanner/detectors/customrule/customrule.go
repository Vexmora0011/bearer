package customrule

import (
	"fmt"

	"github.com/rs/zerolog/log"

	"github.com/bearer/bearer/pkg/scanner/ast/query"
	"github.com/bearer/bearer/pkg/scanner/ast/tree"
	detectortypes "github.com/bearer/bearer/pkg/scanner/detectors/types"
	"github.com/bearer/bearer/pkg/scanner/language"
	"github.com/bearer/bearer/pkg/scanner/ruleset"
	"github.com/bearer/bearer/pkg/scanner/variableshape"

	"github.com/bearer/bearer/pkg/scanner/detectors/customrule/filters"
	"github.com/bearer/bearer/pkg/scanner/detectors/customrule/patternquery"
	"github.com/bearer/bearer/pkg/scanner/detectors/customrule/types"
)

type Pattern struct {
	Index   int
	Pattern string
	Query   patternquery.Query
	Filter  filters.Filter
}

type Detector struct {
	detectortypes.DetectorBase
	rule     *ruleset.Rule
	patterns []Pattern
}

func New(
	language language.Language,
	ruleSet *ruleset.Set,
	variableShapeSet *variableshape.Set,
	querySet *query.Set,
	rule *ruleset.Rule,
) (detectortypes.Detector, error) {
	var compiledPatterns []Pattern
	for i := range rule.Patterns() {
		compiledPattern, err := compilePattern(language, ruleSet, variableShapeSet, querySet, rule, i)
		if err != nil {
			return nil, err
		}

		compiledPatterns = append(compiledPatterns, compiledPattern)
	}

	return &Detector{
		patterns: compiledPatterns,
		rule:     rule,
	}, nil
}

// PatternError is returned by compilePattern, saying which part of the pattern failed
type PatternError struct {
	// IsFilter is true when the pattern compiled but its filters did not
	IsFilter bool
	Err      error
}

func (err *PatternError) Error() string {
	if err.IsFilter {
		return err.Err.Error()
	}

	return fmt.Sprintf("error compiling pattern: %s", err.Err)
}

func (err *PatternError) Unwrap() error {
	return err.Err
}

// ValidatePattern compiles a single pattern of the rule, with its filters, into the given query set.
// Any error is a *PatternError.
func ValidatePattern(
	language language.Language,
	ruleSet *ruleset.Set,
	variableShapeSet *variableshape.Set,
	querySet *query.Set,
	rule *ruleset.Rule,
	patternIndex int,
) error {
	_, err := compilePattern(language, ruleSet, variableShapeSet, querySet, rule, patternIndex)
	return err
}

func compilePattern(
	language language.Language,
	ruleSet *ruleset.Set,
	variableShapeSet *variableshape.Set,
	querySet *query.Set,
	rule *ruleset.Rule,
	patternIndex int,
) (Pattern, error) {
	pattern := rule.Patterns()[patternIndex]
	variableShape := variableShapeSet.Shape(rule)

	patternQuery, err := patternquery.Compile(
		language,
		querySet,
		rule.ID(),
		patternIndex,
		pattern.Pattern,
		pattern.Focus,
		variableShape,
	)
	if err != nil {
		return Pattern{}, &PatternError{Err: err}
	}

	filter, err := translateFiltersTop(ruleSet, variableShapeSet, variableShape, pattern.Filters)
	if err != nil {
		return Pattern{}, &PatternError{IsFilter: true, Err: err}
	}

	return Pattern{
		Index:   patternIndex,
		Pattern: pattern.Pattern,
		Query:   patternQuery,
		Filter:  filter,
	}, nil
}

func (detector *Detector) Rule() *ruleset.Rule {
	return detector.rule
}

func (detector *Detector) DetectAt(
	node *tree.Node,
	detectorContext detectortypes.Context,
) ([]interface{}, error) {
	if log.Trace().Enabled() {
		log.Trace().Msgf("DetectAt: rule=%s, node=%s", detector.rule.ID(), node.Debug())
	}
	var detectionsData []interface{}

	for _, pattern := range detector.patterns {
		results, err := pattern.Query.MatchAt(node)
		if err != nil {
			return nil, err
		}

		if log.Trace().Enabled() {
			if len(results) != 0 {
				log.Trace().Msgf("pattern %s matched (without filters) at node=%s", pattern.Query.ID(), node.Debug())
			} else {
				log.Trace().Msgf("pattern %s did not match at node=%s", pattern.Query.ID(), node.Debug())
			}
		}

		for _, result := range results {
			filterResult, err := pattern.Filter.Evaluate(detectorContext, result.Variables)
			if err != nil {
				return nil, err
			}
			if filterResult == nil || len(filterResult.Matches()) == 0 {
				log.Trace().Msg("filters didn't match")
				continue
			}

			for _, match := range filterResult.Matches() {
				detectionsData = append(detectionsData, types.Data{
					Pattern:   pattern.Pattern,
					Datatypes: match.DatatypeDetections(),
					Variables: match.Variables(),
					Value:     match.Value(),
				})
			}

			if log.Trace().Enabled() {
				log.Trace().Msgf("filters matched for %s at %s", pattern.Query.ID(), node.Debug())
			}
		}
	}

	return detectionsData, nil
}
