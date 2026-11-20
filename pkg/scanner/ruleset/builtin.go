package ruleset

var (
	BuiltinObjectRule = &Rule{
		index:    0,
		id:       "object",
		ruleType: RuleTypeBuiltin,
	}

	BuiltinStringRule = &Rule{
		index:    1,
		id:       "string",
		ruleType: RuleTypeBuiltin,
	}

	BuiltinDatatypeRule = &Rule{
		index:    2,
		id:       "datatype",
		ruleType: RuleTypeBuiltin,
	}

	BuiltinInsecureURLRule = &Rule{
		index:    3,
		id:       "insecure_url",
		ruleType: RuleTypeBuiltin,
	}

	BuiltinStringLiteralRule = &Rule{
		index:    4,
		id:       "string_literal",
		ruleType: RuleTypeBuiltin,
	}

	// index in the slice and the index number above must match
	builtinRules = []*Rule{
		BuiltinObjectRule,
		BuiltinStringRule,
		BuiltinDatatypeRule,
		BuiltinInsecureURLRule,
		BuiltinStringLiteralRule,
	}
)

// IsBuiltinRuleID returns whether the ID belongs to one of the engine's built-in rules, which other
// rules cannot use
func IsBuiltinRuleID(id string) bool {
	for _, rule := range builtinRules {
		if rule.id == id {
			return true
		}
	}

	return false
}
