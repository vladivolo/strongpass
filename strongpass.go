// Package strongpass provides password strength validation 
package strongpass

type ValidationRule struct {
}

type Validator struct {
  rules []ValidationRule
}

type ValidationResult struct {
  strength int
  warnings []string
  errors []string
}

func NewValidator() *Validator {
  return &Validator{}
}

func (validator *Validator) Validate(pw string) (ValidationResult) {
  result := ValidationResult{}

  return result
}

