// Package strongpass provides password strength validation
package strongpass

import (
	"math"
	"strconv"
	"strings"
)

const numerals string = "1234567890123456789098765432100007894561230000741852963000321654987"
const qwertyRow1 string = "qwertyuiop"
const qwertyRow2 string = "asdfghjkl"
const qwertyRow3 string = "zxcvbnm"
const qwertyNumberCol string = "1q2w3e4r5t6y7u8i9o0p"
const qwertyCols string = "1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik9ol0p"
const qwertyRowBy3 string = "123qweasdzxc456rtyfghvbn789uiojklm"

var allSpans = []string{qwertyRow1, qwertyRow2, qwertyRow3, alphabet, numerals, qwertyNumberCol, qwertyCols, qwertyRowBy3}

const alphabet string = "abcdefghijklmnopqrstuvwxyz"
const upperAlphabet string = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
const numbers string = "0123456789"
const special string = "!@#$%^&*-_=+? "

var commonPws = []string{"", "root", "master", "1234", "letmein",
	"password", "qwerty", "admin", "shadow", "hello", "password1", "trustno1",
	"abc", "iloveyou", "monkey", "123321", "dragon", "123", "myspace", "1212",
	"123abc", "tinkle", "princess", "football", "jessica", "love", "lucky", "baby",
	"soccer", "golden", "strawberry", "orlando", "bismillah", "carmen", "angelo", "tiffany",
	"rabbit", "rainbow", "angel", "tiffany", "sexy", "pass", "beauty", "bonjour", "test", "tester",
	"jesus", "christian", "killer", "jordan", "lebron", "money", "number", "hunter", "loveme",
	"pokemon", "internet", "batman", "orange", "brandon", "london", "lol", "chris", "linkedin",
	"baseball", "basketball", "purple", "yellow", "green", "secret", "passwort", "kakashi", "naruto",
	"ashley", "steven", "nicole", "matthew", "michelle", "computer", "andrew", "red", "jasmine",
	"chocolate", "heather", "peanut", "Password", "ginger", "melissa", "stupid", "newyork", "monster",
	"crazy", "tiger", "dolphin"}

var commonSuffixes = []string{"1", "2", "3", "12", "123", "1234", "10", "13", "4", "5", "6", "7", "8", "9", "0", "!", "23", "11"}

type CheckRule func(string) string

type ValidationRule struct {
	description string
	check       CheckRule
}

type Validator struct {
	rules []ValidationRule
}

type ValidationResult struct {
	strength float64
	warnings []string
	errors   []string
}

func (res ValidationResult) HasErrors() bool {
	return len(res.errors) > 0
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

	result.strength = entropy(pw)
	return result
}

func entropy(pw string) float64 {
	charPool := make(map[string]int)
	charPool[alphabet] = len(alphabet)
	charPool[upperAlphabet] = len(upperAlphabet)
	charPool[numbers] = len(numbers)
	charPool[special] = len(special)

	length := len(pw)
	if length == 0 {
		return 0.0
	}
	digits := 0

	for k, _ := range charPool {
		for _, c := range pw {
			if strings.Contains(k, string(c)) {
				digits += charPool[k]
				charPool[k] = 0
			}
		}
	}

	if digits < 1 {
		digits = length
	}

	return float64(length) * math.Log2(float64(digits))
}

func (validator *Validator) WithStandardRules() {
	validator.NoCommonPasswords()
	validator.NoEasySpans()
	validator.NoInternalRepetition()
	validator.MinimumCharacterCount()
}

func (validator *Validator) NoCommonPasswords() {
	validator.rules = append(validator.rules, newCommonPasswordsRule())
}

func (validator *Validator) NoEasySpans() {
	validator.rules = append(validator.rules, newEasySpansRule(4))
}

func (validator *Validator) NoInternalRepetition() {
	validator.rules = append(validator.rules, newInternalRepetitionRule(3))
}

func (validator *Validator) MinimumCharacterCount() {
	validator.rules = append(validator.rules, newCharacterCountRule(8))
}

func newCommonPasswordsRule() ValidationRule {
	rule := ValidationRule{}
	rule.description = "Your password contains a commonly used password."
	rule.check = func(pw string) string {
		for _, commonPw := range commonPws {
			if pw == commonPw {
				return "Password is common: '" + commonPw + "'"
			}
			for _, suffix := range commonSuffixes {
				if pw == commonPw+suffix {
					return "Password is common: '" + commonPw + suffix + "'"
				}
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

func newInternalRepetitionRule(length int) ValidationRule {
	rule := ValidationRule{}
	rule.description = "Your password contains repeated strings of characters"
	rule.check = func(pw string) string {
		pwlen := len(pw)
		for i := range pw {
			if i+length > pwlen {
				return ""
			}

			toMatch := pw[i : i+length]
			if strings.Contains(pw[i+length:], toMatch) {
				return "Password contains repeated substring: " + toMatch
			}
		}
		return ""
	}
	return rule
}

func newCharacterCountRule(length int) ValidationRule {
	rule := ValidationRule{}
	rule.description = "Your password is to short. Try adding more characters"
	rule.check = func(pw string) string {
		if len(pw) < length {
			return "Password must be at least " + strconv.Itoa(length) + " characters."
		}
		return ""
	}
	return rule
}
