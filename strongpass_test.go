package strongpass

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestZeroValidationRules(t *testing.T) {
  validator := NewValidator()

  result := validator.Validate("abc123")
  assert.Equal(t, 0, result.strength)
}
