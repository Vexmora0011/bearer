package structurederrors_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bearer/bearer/pkg/structurederrors"
)

func TestBuildReport(t *testing.T) {
	collector := structurederrors.New()
	collector.RegisterRule("rule_b", "rules/b.yml", "")
	collector.Add(structurederrors.Item{
		Severity:    structurederrors.SeverityError,
		Stage:       structurederrors.StageCompile,
		Code:        structurederrors.CodePatternInvalid,
		RuleID:      "rule_a",
		RuleSkipped: true,
	})
	collector.Add(structurederrors.Item{
		Severity: structurederrors.SeverityWarning,
		Stage:    structurederrors.StageLoad,
		Code:     structurederrors.CodeRuleUnknownField,
		RuleID:   "rule_a",
	})

	report := collector.BuildReport([]structurederrors.ScanError{
		{File: "slow.js", Message: "file processing time exceeded"},
		{File: "app.js", Message: "javascript scan failed: cycle found during rule evaluation at x: [rule_a > rule_b > rule_a]"},
		{File: "other.js", Message: "something else"},
	})

	require.NotNil(t, report)
	assert.Equal(t, structurederrors.SchemaVersion, report.SchemaVersion)
	assert.Equal(t, 4, report.Summary.Errors)
	assert.Equal(t, 1, report.Summary.Warnings)
	assert.Equal(t, []string{"rule_a"}, report.Summary.SkippedRuleIDs)

	require.Len(t, report.Items, 5)
	assert.Equal(t, structurederrors.StageLoad, report.Items[0].Stage)
	assert.Equal(t, structurederrors.StageCompile, report.Items[1].Stage)

	scanItems := make(map[string]structurederrors.Item)
	for _, item := range report.Items[2:] {
		scanItems[item.File] = item
	}

	assert.Equal(t, structurederrors.CodeFileTimeout, scanItems["slow.js"].Code)
	assert.Equal(t, structurederrors.CodeFileScanFailed, scanItems["other.js"].Code)

	cycle := scanItems["app.js"]
	assert.Equal(t, structurederrors.CodeRuleCycle, cycle.Code)
	assert.Equal(t, "javascript", cycle.Language)
	assert.Equal(t, "rule_a", cycle.RuleID)
	assert.Equal(t, "rule_b", cycle.RelatedRuleID)

	// building again does not duplicate scan errors
	assert.Len(t, collector.BuildReport(nil).Items, 2)
}

func TestNilCollector(t *testing.T) {
	var collector *structurederrors.Collector

	collector.Add(structurederrors.Item{})
	collector.RegisterRule("a", "a.yml", "")

	assert.False(t, collector.Enabled())
	assert.Nil(t, collector.BuildReport(nil))
}
