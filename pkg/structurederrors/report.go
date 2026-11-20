package structurederrors

import (
	"regexp"
	"slices"
	"strings"
)

// SchemaVersion is bumped on any breaking change to the Report structure
const SchemaVersion = "1"

type Summary struct {
	Errors   int `json:"errors" yaml:"errors"`
	Warnings int `json:"warnings" yaml:"warnings"`
	// SkippedRuleIDs lists the rules that were left out of the scan because of an error
	SkippedRuleIDs []string `json:"skipped_rule_ids" yaml:"skipped_rule_ids"`
}

// Report is the structured_errors section of a report
type Report struct {
	SchemaVersion string  `json:"schema_version" yaml:"schema_version"`
	Summary       Summary `json:"summary" yaml:"summary"`
	Items         []Item  `json:"items" yaml:"items"`
}

// ScanError is an error from scanning a single file
type ScanError struct {
	File    string
	Message string
}

// BuildReport returns the structured errors report, including the given file scan errors. It returns nil
// when the collector is disabled.
func (collector *Collector) BuildReport(scanErrors []ScanError) *Report {
	if !collector.Enabled() {
		return nil
	}

	items := collector.Items()
	for _, scanError := range scanErrors {
		items = append(items, collector.withSource(fromScanError(scanError)))
	}
	sortItems(items)

	summary := Summary{SkippedRuleIDs: []string{}}
	for _, item := range items {
		switch item.Severity {
		case SeverityError:
			summary.Errors++
		case SeverityWarning:
			summary.Warnings++
		}

		if item.RuleSkipped && item.RuleID != "" && !slices.Contains(summary.SkippedRuleIDs, item.RuleID) {
			summary.SkippedRuleIDs = append(summary.SkippedRuleIDs, item.RuleID)
		}
	}
	slices.Sort(summary.SkippedRuleIDs)

	return &Report{
		SchemaVersion: SchemaVersion,
		Summary:       summary,
		Items:         items,
	}
}

// timeoutMessage matches the error the worker gives when a file takes too long
const timeoutMessage = "file processing time exceeded"

var (
	languagePrefixPattern = regexp.MustCompile(`^(\w+) scan failed: `)
	cyclePattern          = regexp.MustCompile(`cycle found during rule evaluation at .*: \[(.*) > ([^\s\]]+)\]`)
)

func fromScanError(scanError ScanError) Item {
	item := Item{
		Severity: SeverityError,
		Stage:    StageScan,
		Code:     CodeFileScanFailed,
		Message:  scanError.Message,
		File:     scanError.File,
	}

	if match := languagePrefixPattern.FindStringSubmatch(scanError.Message); match != nil {
		item.Language = match[1]
	}

	switch {
	case strings.Contains(scanError.Message, timeoutMessage):
		item.Code = CodeFileTimeout
	case cyclePattern.MatchString(scanError.Message):
		match := cyclePattern.FindStringSubmatch(scanError.Message)
		item.Code = CodeRuleCycle
		item.RuleID = match[2]
		chain := strings.Split(match[1], " > ")
		item.RelatedRuleID = chain[len(chain)-1]
	}

	return item
}
