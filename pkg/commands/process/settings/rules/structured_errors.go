package rules

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/bearer/bearer/pkg/commands/process/settings"
	"github.com/bearer/bearer/pkg/structurederrors"
	"github.com/bearer/bearer/pkg/util/set"
)

// loadContext holds what custom rule loading needs only when structured errors are enabled. A nil
// loadContext disables structured errors.
type loadContext struct {
	errorCollector   *structurederrors.Collector
	knownLanguageIDs set.Set[string]
}

func newLoadContext(errorCollector *structurederrors.Collector, knownLanguageIDs []string) *loadContext {
	if !errorCollector.Enabled() {
		return nil
	}

	languages := set.New[string]()
	languages.AddAll(knownLanguageIDs)

	return &loadContext{errorCollector: errorCollector, knownLanguageIDs: languages}
}

func (loadCtx *loadContext) structuredErrors() *structurederrors.Collector {
	if loadCtx == nil {
		return nil
	}

	return loadCtx.errorCollector
}

func (loadCtx *loadContext) addLanguageErrors(ruleID, rulePath string, languageIDs []string) {
	if loadCtx == nil || len(loadCtx.knownLanguageIDs) == 0 {
		return
	}

	knownLanguageIDs := loadCtx.knownLanguageIDs.Items()
	slices.Sort(knownLanguageIDs)

	for _, languageID := range languageIDs {
		if loadCtx.knownLanguageIDs.Has(languageID) {
			continue
		}

		loadCtx.errorCollector.Add(structurederrors.Item{
			Severity: structurederrors.SeverityError,
			Stage:    structurederrors.StageLoad,
			Code:     structurederrors.CodeRuleUnknownLanguage,
			Message: fmt.Sprintf(
				"unknown language '%s'; supported languages are [%s]",
				languageID,
				strings.Join(knownLanguageIDs, ", "),
			),
			RuleID:   ruleID,
			RuleFile: rulePath,
		})
	}
}

var yamlLinePattern = regexp.MustCompile(`^(?:yaml: )?line (\d+): (.*)$`)

// addYAMLErrors reports a rule file that could not be parsed, with one item per problem
// yaml reports
func addYAMLErrors(errorCollector *structurederrors.Collector, rulePath string, err error) {
	var messages []string

	var typeError *yaml.TypeError
	if errors.As(err, &typeError) {
		messages = typeError.Errors
	} else {
		messages = []string{err.Error()}
	}

	for _, message := range messages {
		position, message := splitYAMLLine(message)

		errorCollector.Add(structurederrors.Item{
			Severity:    structurederrors.SeverityError,
			Stage:       structurederrors.StageLoad,
			Code:        structurederrors.CodeRuleYAMLInvalid,
			Message:     message,
			RuleFile:    rulePath,
			Position:    position,
			RuleSkipped: true,
		})
	}
}

var unknownFieldPattern = regexp.MustCompile(`^field (\S+) not found in type (\S+)$`)

// schemaOnlyFields are valid in the rule schema but not read by the engine
var schemaOnlyFields = map[string]bool{
	"cloud_code_suggestions": true,
}

// addUnknownFieldWarnings warns about keys in a rule file that the engine ignores, as they are
// usually a typo (eg. `pattern:` instead of `patterns:`)
func addUnknownFieldWarnings(errorCollector *structurederrors.Collector, ruleID, rulePath string, entry []byte) {
	decoder := yaml.NewDecoder(bytes.NewReader(entry))
	decoder.KnownFields(true)

	var definition settings.RuleDefinition
	err := decoder.Decode(&definition)

	var typeError *yaml.TypeError
	if !errors.As(err, &typeError) {
		return
	}

	for _, rawMessage := range typeError.Errors {
		position, message := splitYAMLLine(rawMessage)

		match := unknownFieldPattern.FindStringSubmatch(message)
		if match == nil || schemaOnlyFields[match[1]] {
			continue
		}

		errorCollector.Add(structurederrors.Item{
			Severity: structurederrors.SeverityWarning,
			Stage:    structurederrors.StageLoad,
			Code:     structurederrors.CodeRuleUnknownField,
			Message:  fmt.Sprintf("unknown field '%s' is ignored", match[1]),
			RuleID:   ruleID,
			RuleFile: rulePath,
			Position: position,
		})
	}
}

func splitYAMLLine(message string) (*structurederrors.Position, string) {
	message = strings.TrimSpace(message)

	match := yamlLinePattern.FindStringSubmatch(message)
	if match == nil {
		return nil, strings.TrimPrefix(message, "yaml: ")
	}

	line, err := strconv.Atoi(match[1])
	if err != nil {
		return nil, message
	}

	return &structurederrors.Position{Line: line}, match[2]
}
