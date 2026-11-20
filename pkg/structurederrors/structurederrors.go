// Package structurederrors collects structured problems found while loading, validating, compiling and
// running rules, so that tools (such as an agent writing rules) can act on them without parsing log
// output.
//
// Collection is opt-in: a nil *Collector is valid and ignores everything, so call sites do not need
// to check whether structured errors are enabled.
package structurederrors

import (
	"cmp"
	"slices"
	"sync"
)

type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
)

// Stage is the phase of the scan in which the problem was found.
type Stage string

const (
	// StageLoad covers reading and parsing rule files
	StageLoad Stage = "load"
	// StageValidate covers checks on a parsed rule definition (imports, references, metadata)
	StageValidate Stage = "validate"
	// StageCompile covers compiling rule patterns and filters for a language
	StageCompile Stage = "compile"
	// StageScan covers problems found while scanning files
	StageScan Stage = "scan"
)

// Code identifies the kind of problem. Codes are stable and intended to be matched on by tools;
// messages are for humans and may change.
type Code string

const (
	CodeRuleReadFailed         Code = "rule_read_failed"
	CodeRuleYAMLInvalid        Code = "rule_yaml_invalid"
	CodeRuleUnknownField       Code = "rule_unknown_field"
	CodeRuleMissingMetadata    Code = "rule_missing_metadata"
	CodeRuleMissingID          Code = "rule_missing_id"
	CodeRuleDuplicateID        Code = "rule_duplicate_id"
	CodeRuleUnknownLanguage    Code = "rule_unknown_language"
	CodeRuleLanguageNotFound   Code = "rule_language_not_in_target"
	CodeImportUnknownRule      Code = "import_unknown_rule"
	CodeImportNotShared        Code = "import_not_shared"
	CodeFilterUnknownRule      Code = "filter_unknown_rule"
	CodeSanitizerUnknownRule   Code = "sanitizer_unknown_rule"
	CodeSharedRuleInvalidField Code = "shared_rule_invalid_field"
	CodePatternInvalid         Code = "pattern_invalid"
	CodePatternQueryInvalid    Code = "pattern_query_invalid"
	CodeFilterInvalid          Code = "filter_invalid"
	CodeRuleSetInvalid         Code = "rule_set_invalid"
	CodeRuleDependencyInvalid  Code = "rule_dependency_invalid"
	CodeRuleCycle              Code = "rule_cycle"
	CodeFileTimeout            Code = "file_timeout"
	CodeFileScanFailed         Code = "file_scan_failed"
)

// Position is a 1-based line and column.
type Position struct {
	Line   int `json:"line" yaml:"line"`
	Column int `json:"column,omitempty" yaml:"column,omitempty"`
}

type Item struct {
	Severity Severity `json:"severity" yaml:"severity"`
	Stage    Stage    `json:"stage" yaml:"stage"`
	Code     Code     `json:"code" yaml:"code"`
	Message  string   `json:"message" yaml:"message"`
	// RuleID is the rule the problem belongs to. For an auxiliary rule this is the auxiliary ID, and
	// ParentRuleID is the rule that defines it.
	RuleID       string `json:"rule_id,omitempty" yaml:"rule_id,omitempty"`
	ParentRuleID string `json:"parent_rule_id,omitempty" yaml:"parent_rule_id,omitempty"`
	// RuleFile is the path of the rule's YAML file
	RuleFile string `json:"rule_file,omitempty" yaml:"rule_file,omitempty"`
	// PatternIndex is the 0-based index into the rule's `patterns` list
	PatternIndex *int   `json:"pattern_index,omitempty" yaml:"pattern_index,omitempty"`
	Pattern      string `json:"pattern,omitempty" yaml:"pattern,omitempty"`
	Language     string `json:"language,omitempty" yaml:"language,omitempty"`
	// RelatedRuleID is another rule involved in the problem (eg. the missing import)
	RelatedRuleID string `json:"related_rule_id,omitempty" yaml:"related_rule_id,omitempty"`
	// File is the scanned source file, for scan stage problems
	File string `json:"file,omitempty" yaml:"file,omitempty"`
	// Position is within RuleFile for load stage problems, within Pattern for compile stage problems
	// and within File for scan stage problems
	Position *Position `json:"position,omitempty" yaml:"position,omitempty"`
	// RuleSkipped is true when the rule was left out of the scan because of this problem
	RuleSkipped bool `json:"rule_skipped,omitempty" yaml:"rule_skipped,omitempty"`
}

type ruleSource struct {
	file     string
	parentID string
}

// Collector gathers structured errors. It is safe for concurrent use. A nil Collector discards everything.
type Collector struct {
	mutex       sync.Mutex
	items       []Item
	ruleSources map[string]ruleSource
}

func New() *Collector {
	return &Collector{ruleSources: make(map[string]ruleSource)}
}

func (collector *Collector) Enabled() bool {
	return collector != nil
}

// RegisterRule records where a rule came from, so later items for it are filled in with its
// file (and parent, for auxiliary rules). Only registered rules are checked at the compile stage.
func (collector *Collector) RegisterRule(id, file, parentID string) {
	if collector == nil {
		return
	}

	collector.mutex.Lock()
	defer collector.mutex.Unlock()

	collector.ruleSources[id] = ruleSource{file: file, parentID: parentID}
}

// IsRegisteredRule reports whether the rule was registered with RegisterRule
func (collector *Collector) IsRegisteredRule(id string) bool {
	if collector == nil {
		return false
	}

	collector.mutex.Lock()
	defer collector.mutex.Unlock()

	_, exists := collector.ruleSources[id]
	return exists
}

// ParentRuleID returns the rule that defines the given auxiliary rule, if any
func (collector *Collector) ParentRuleID(id string) string {
	if collector == nil {
		return ""
	}

	collector.mutex.Lock()
	defer collector.mutex.Unlock()

	return collector.ruleSources[id].parentID
}

func (collector *Collector) Add(item Item) {
	if collector == nil {
		return
	}

	item = collector.withSource(item)

	collector.mutex.Lock()
	defer collector.mutex.Unlock()

	collector.items = append(collector.items, item)
}

// withSource fills in the rule file and parent rule of a item from the registered rules
func (collector *Collector) withSource(item Item) Item {
	collector.mutex.Lock()
	defer collector.mutex.Unlock()

	if source, exists := collector.ruleSources[item.RuleID]; exists {
		if item.RuleFile == "" {
			item.RuleFile = source.file
		}
		if item.ParentRuleID == "" {
			item.ParentRuleID = source.parentID
		}
	}

	return item
}

// Items returns the collected items in a stable order. It never returns nil for an
// enabled collector, so an empty list is reported as `[]`.
func (collector *Collector) Items() []Item {
	if collector == nil {
		return nil
	}

	collector.mutex.Lock()
	defer collector.mutex.Unlock()

	result := slices.Clone(collector.items)
	if result == nil {
		result = []Item{}
	}

	sortItems(result)

	return result
}

func sortItems(items []Item) {
	slices.SortStableFunc(items, func(a, b Item) int {
		return cmp.Or(
			cmp.Compare(stageOrder(a.Stage), stageOrder(b.Stage)),
			cmp.Compare(a.RuleFile, b.RuleFile),
			cmp.Compare(a.RuleID, b.RuleID),
			cmp.Compare(patternIndex(a), patternIndex(b)),
			cmp.Compare(a.Language, b.Language),
			cmp.Compare(a.File, b.File),
		)
	})
}

func stageOrder(stage Stage) int {
	switch stage {
	case StageLoad:
		return 0
	case StageValidate:
		return 1
	case StageCompile:
		return 2
	default:
		return 3
	}
}

func patternIndex(item Item) int {
	if item.PatternIndex == nil {
		return -1
	}

	return *item.PatternIndex
}

// Index returns a pointer to the given int, for use as a PatternIndex
func Index(index int) *int {
	return &index
}
