package stablenet

import "errors"

// Validator management errors.
var (
	ErrValidatorExists   = errors.New("validator already exists")
	ErrValidatorNotFound = errors.New("validator not found")
	ErrNoValidators      = errors.New("no validators in the set")
)

// Stablecoin errors.
var (
	ErrMinterNotFound     = errors.New("minter not found")
	ErrInsufficientSupply = errors.New("insufficient supply")
	ErrUnauthorized       = errors.New("unauthorized operation")
)
