// Package strongpass provides password strength validation
package strongpass

import (
	"strings"
)

const numerals string = "1234567890123456789"
const qwertyRow1 string = "qwertyuiop"
const qwertyRow2 string = "asdfghjkl"
const qwertyRow3 string = "zxcvbnm"
const alphabet string = "abcdefghijklmnopqrstuvwxyz"

type CheckRule func(string) string

type ValidationRule struct {
	description string
	check       CheckRule
}

type Validator struct {
	rules []ValidationRule
}

type ValidationResult struct {
	strength int
	warnings []string
	errors   []string
}

func NewValidator() *Validator {
	return &Validator{rules: make([]ValidationRule, 0)}
}

func (validator *Validator) Validate(pw string) ValidationResult {
	result := ValidationResult{errors: make([]string, 0)}

	for _, rule := range validator.rules {
		errorMsg := rule.check(pw)
		if errorMsg != "" {
			result.errors = append(result.errors, errorMsg)
		}
	}

	return result
}

func (validator *Validator) NoCommonPasswords() {
	validator.rules = append(validator.rules, newCommonPasswordsRule())
}

func (validator *Validator) NoEasySpans() {
	validator.rules = append(validator.rules, newEasySpansRule(4))
}

func newCommonPasswordsRule() ValidationRule {
	rule := ValidationRule{}
	rule.description = "Your password contains a commonly used password."
	rule.check = func(pw string) string {
		commonPws := []string{"root", "master", "1234", "letmein",
			"password", "qwerty", "admin", "shadow", "hello", "password1", "trustno1"}
		for _, commonPw := range commonPws {
			if strings.Contains(pw, commonPw) {
				return "Password contains string '" + commonPw + "'"
			}
		}
		return ""
	}
	return rule
}

func newEasySpansRule(length int) ValidationRule {
	rule := ValidationRule{}
	rule.description = "Your password contains easily guessable strings of characters."
	rule.check = func(pw string) string {
		allSpans := []string{qwertyRow1, qwertyRow2, qwertyRow3, alphabet, numerals}
		for _, span := range allSpans {
			for m, _ := range span {
				if len(span[m:]) >= length {
					run := span[m : m+length]
					if strings.Contains(pw, run) {
						return "Password contains '" + run + "'"
					}
				}
			}

		}
		return ""
	}
	return rule
}
