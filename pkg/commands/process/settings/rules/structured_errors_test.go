package rules

import (
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bearer/bearer/pkg/commands/process/settings"
	"github.com/bearer/bearer/pkg/structurederrors"
)

func loadWithStructuredErrors(t *testing.T, files map[string]string) (map[string]settings.RuleDefinition, []structurederrors.Item) {
	t.Helper()

	dir := fstest.MapFS{}
	for name, content := range files {
		dir[name] = &fstest.MapFile{Data: []byte(content)}
	}

	errorCollector := structurederrors.New()
	definitions := make(map[string]settings.RuleDefinition)

	_, err := loadDefinitions(
		definitions,
		[]ruleDir{{path: "rules", fs: dir}},
		false,
		[]string{"python"},
		nil,
		newLoadContext(errorCollector, []string{"python", "ruby"}),
	)
	require.NoError(t, err)

	return definitions, errorCollector.Items()
}

func codes(items []structurederrors.Item) []structurederrors.Code {
	result := make([]structurederrors.Code, len(items))
	for i, item := range items {
		result[i] = item.Code
	}

	return result
}

func TestLoadDefinitionsStructuredErrors(t *testing.T) {
	t.Run("reports invalid YAML and keeps loading other rules", func(t *testing.T) {
		definitions, items := loadWithStructuredErrors(t, map[string]string{
			"broken.yml": "languages: [python\npatterns:\n  - foo\n",
			"good.yml":   "languages: [python]\npatterns: [foo]\nmetadata:\n  id: good\n",
		})

		assert.Contains(t, definitions, "good")
		require.Len(t, items, 1)
		assert.Equal(t, structurederrors.CodeRuleYAMLInvalid, items[0].Code)
		assert.Equal(t, "rules/broken.yml", items[0].RuleFile)
		assert.Equal(t, &structurederrors.Position{Line: 1}, items[0].Position)
		assert.True(t, items[0].RuleSkipped)
	})

	t.Run("warns about unknown fields", func(t *testing.T) {
		definitions, items := loadWithStructuredErrors(t, map[string]string{
			"typo.yml": "languages: [python]\npattern: [foo]\npatterns: [bar]\nmetadata:\n  id: typo\n  cloud_code_suggestions: true\n",
		})

		assert.Contains(t, definitions, "typo")
		require.Len(t, items, 1)
		assert.Equal(t, structurederrors.SeverityWarning, items[0].Severity)
		assert.Equal(t, structurederrors.CodeRuleUnknownField, items[0].Code)
		assert.Equal(t, "typo", items[0].RuleID)
		assert.Equal(t, &structurederrors.Position{Line: 2}, items[0].Position)
	})

	t.Run("reports unknown languages and languages missing from the target", func(t *testing.T) {
		_, items := loadWithStructuredErrors(t, map[string]string{
			"lang.yml": "languages: [pyhton]\npatterns: [foo]\nmetadata:\n  id: lang\n",
		})

		assert.Equal(t, []structurederrors.Code{structurederrors.CodeRuleUnknownLanguage, structurederrors.CodeRuleLanguageNotFound}, codes(items))
	})

	t.Run("reports missing metadata and id", func(t *testing.T) {
		_, items := loadWithStructuredErrors(t, map[string]string{
			"a.yml": "languages: [python]\npatterns: [foo]\n",
			"b.yml": "languages: [python]\npatterns: [foo]\nmetadata:\n  description: x\n",
		})

		assert.Equal(t, []structurederrors.Code{structurederrors.CodeRuleMissingMetadata, structurederrors.CodeRuleMissingID}, codes(items))
	})

	t.Run("reports duplicate rule IDs and keeps the first", func(t *testing.T) {
		definitions, items := loadWithStructuredErrors(t, map[string]string{
			"a.yml": "languages: [python]\npatterns: [foo]\nmetadata:\n  id: dup\n",
			"b.yml": "languages: [python]\npatterns: [bar]\nmetadata:\n  id: dup\n",
		})

		assert.Equal(t, "foo", definitions["dup"].Patterns[0].Pattern)
		require.Len(t, items, 1)
		assert.Equal(t, structurederrors.CodeRuleDuplicateID, items[0].Code)
		assert.Equal(t, "rules/b.yml", items[0].RuleFile)
	})

	t.Run("reports validation issues with the related rule", func(t *testing.T) {
		definitions, items := loadWithStructuredErrors(t, map[string]string{
			"importer.yml": `
languages: [python]
imports: [missing_shared, not_shared]
patterns:
  - pattern: foo($<X>)
    filters:
      - variable: X
        detection: other
metadata:
  id: importer
`,
			"not_shared.yml": "languages: [python]\npatterns: [foo]\nmetadata:\n  id: not_shared\n",
		})

		assert.NotContains(t, definitions, "importer")
		assert.ElementsMatch(t, []structurederrors.Code{
			structurederrors.CodeImportUnknownRule,
			structurederrors.CodeImportNotShared,
			structurederrors.CodeFilterUnknownRule,
		}, codes(items))

		for _, item := range items {
			assert.Equal(t, "importer", item.RuleID)
			assert.Equal(t, "rules/importer.yml", item.RuleFile)
			assert.NotEmpty(t, item.RelatedRuleID)
			assert.True(t, item.RuleSkipped)
		}
	})
}
