package strongpass

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestZeroValidationRules(t *testing.T) {
	validator := NewValidator()

	result := validator.Validate("")
	assert.Equal(t, 0.0, result.strength)
}

func TestEntropyCalculationPool26(t *testing.T) {
	validator := NewValidator()

	result := validator.Validate("laval")
	assert.InDelta(t, 23.502, result.strength, 0.001)
}

func TestEntropyCalculationPool36(t *testing.T) {
	validator := NewValidator()

	result := validator.Validate("l0val")
	assert.InDelta(t, 25.8496, result.strength, 0.001)
}

func TestEntropyCalculationPool52(t *testing.T) {
	validator := NewValidator()

	result := validator.Validate("lavaL")
	assert.InDelta(t, 28.502, result.strength, 0.001)
}

func TestEntropyCalculationPool62(t *testing.T) {
	validator := NewValidator()

	result := validator.Validate("la5aL")
	assert.InDelta(t, 29.7709, result.strength, 0.001)
}

func TestEntropyCalculationPoolSpecial(t *testing.T) {
	validator := NewValidator()

	result := validator.Validate("!a5aL")
	assert.InDelta(t, 31.239, result.strength, 0.001)
}

func TestEntropyCalculationStrong(t *testing.T) {
	validator := NewValidator()

	result := validator.Validate("pvt$10rKmurL")
	assert.InDelta(t, 74.975, result.strength, 0.001)
}

func TestCommonPasswordsRule(t *testing.T) {
	validator := NewValidator()
	validator.NoCommonPasswords()

	assert.Equal(t, "Password is common: 'letmein'", validator.Validate("letmein").errors[0])
	assert.Equal(t, "Password is common: 'password'", validator.Validate("password").errors[0])
	assert.Equal(t, "Password is common: 'hello'", validator.Validate("hello").errors[0])
	assert.Equal(t, 0, len(validator.Validate("hhelloo").errors))
}

func TestEasySpansRule(t *testing.T) {
	validator := NewValidator()
	validator.NoEasySpans()

	assert.Equal(t, "Password contains 'qwer'", validator.Validate("0qwerty0").errors[0])
	assert.Equal(t, "Password contains 'vwxy'", validator.Validate("ABCvwxyz").errors[0])
	assert.Equal(t, "Password contains '0123'", validator.Validate("myPas012365").errors[0])
}

func TestInternalRepetitionRule(t *testing.T) {
	validator := NewValidator()
	validator.NoInternalRepetition()

	assert.Equal(t, "Password contains repeated substring: gre", validator.Validate("gregre").errors[0])
	assert.Equal(t, "Password contains repeated substring: cat", validator.Validate("a3catb4cat").errors[0])
	assert.Equal(t, "Password contains repeated substring: paz", validator.Validate("paz0paz0").errors[0])
	assert.Equal(t, 0, len(validator.Validate("ab1ab2cd1cd2be0be2").errors))
}

func TestCharacterCountRule(t *testing.T) {
	validator := NewValidator()
	validator.MinimumCharacterCount()

	assert.Equal(t, "Password must be at least 8 characters.", validator.Validate("abadaqe").errors[0])
	assert.Equal(t, 0, len(validator.Validate("panamare").errors))
}

func TestMultipleRules(t *testing.T) {
	validator := NewValidator()
	validator.WithStandardRules()

	result := validator.Validate("asdfasd")

	assert.Equal(t, "Password contains 'asdf'", result.errors[0])
	assert.Equal(t, "Password contains repeated substring: asd", result.errors[1])
	assert.Equal(t, "Password must be at least 8 characters.", result.errors[2])
}
