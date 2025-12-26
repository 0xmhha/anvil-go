package stablenet

import (
	"crypto/sha256"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Validator represents a StableNet validator.
type Validator struct {
	Address      common.Address
	Operator     common.Address
	BLSPublicKey []byte
}

// ValidatorManager manages the validator set.
type ValidatorManager struct {
	validators     []Validator
	validatorIndex map[common.Address]int
	gasTip         *big.Int

	mu sync.RWMutex
}

// NewValidatorManager creates a new validator manager.
func NewValidatorManager() *ValidatorManager {
	return &ValidatorManager{
		validators:     make([]Validator, 0),
		validatorIndex: make(map[common.Address]int),
		gasTip:         big.NewInt(0),
	}
}

// AddValidator adds a validator to the set.
func (m *ValidatorManager) AddValidator(addr, operator common.Address, blsKey []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if validator already exists
	if _, exists := m.validatorIndex[addr]; exists {
		return ErrValidatorExists
	}

	validator := Validator{
		Address:      addr,
		Operator:     operator,
		BLSPublicKey: blsKey,
	}

	m.validators = append(m.validators, validator)
	m.validatorIndex[addr] = len(m.validators) - 1

	return nil
}

// RemoveValidator removes a validator from the set.
func (m *ValidatorManager) RemoveValidator(addr common.Address) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	idx, exists := m.validatorIndex[addr]
	if !exists {
		return ErrValidatorNotFound
	}

	// Remove from slice
	m.validators = append(m.validators[:idx], m.validators[idx+1:]...)

	// Rebuild index
	m.validatorIndex = make(map[common.Address]int)
	for i, v := range m.validators {
		m.validatorIndex[v.Address] = i
	}

	return nil
}

// GetValidator returns a validator by address.
func (m *ValidatorManager) GetValidator(addr common.Address) (*Validator, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	idx, exists := m.validatorIndex[addr]
	if !exists {
		return nil, false
	}

	v := m.validators[idx]
	return &v, true
}

// GetValidators returns all validators.
func (m *ValidatorManager) GetValidators() []Validator {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]Validator, len(m.validators))
	copy(result, m.validators)
	return result
}

// GetValidatorAddresses returns all validator addresses.
func (m *ValidatorManager) GetValidatorAddresses() []common.Address {
	m.mu.RLock()
	defer m.mu.RUnlock()

	addrs := make([]common.Address, len(m.validators))
	for i, v := range m.validators {
		addrs[i] = v.Address
	}
	return addrs
}

// Count returns the number of validators.
func (m *ValidatorManager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return len(m.validators)
}

// SetGasTip sets the gas tip.
func (m *ValidatorManager) SetGasTip(gasTip *big.Int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.gasTip = new(big.Int).Set(gasTip)
}

// GetGasTip returns the current gas tip.
func (m *ValidatorManager) GetGasTip() *big.Int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return new(big.Int).Set(m.gasTip)
}

// GetProposer returns the proposer for a given block number using round-robin.
func (m *ValidatorManager) GetProposer(blockNumber uint64) (common.Address, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.validators) == 0 {
		return common.Address{}, ErrNoValidators
	}

	idx := blockNumber % uint64(len(m.validators))
	return m.validators[idx].Address, nil
}

// Clear removes all validators and resets gas tip.
func (m *ValidatorManager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.validators = make([]Validator, 0)
	m.validatorIndex = make(map[common.Address]int)
	m.gasTip = big.NewInt(0)
}

// CalculateMappingSlot calculates the storage slot for a mapping key.
func CalculateMappingSlot(slot common.Hash, key common.Address) common.Hash {
	// keccak256(abi.encode(key, slot))
	data := make([]byte, 64)
	copy(data[12:32], key.Bytes())
	copy(data[32:64], slot.Bytes())
	return crypto.Keccak256Hash(data)
}

// CalculateDynamicSlot calculates the storage slot for a dynamic array element.
func CalculateDynamicSlot(baseSlot common.Hash, index *big.Int) common.Hash {
	// keccak256(baseSlot) + index
	baseHash := crypto.Keccak256Hash(baseSlot.Bytes())
	result := new(big.Int).Add(baseHash.Big(), index)
	return common.BigToHash(result)
}

// HashBLSKey hashes a BLS public key for storage lookup.
func HashBLSKey(blsKey []byte) common.Hash {
	hash := sha256.Sum256(blsKey)
	return common.BytesToHash(hash[:])
}
