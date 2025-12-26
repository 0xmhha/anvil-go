package stablenet

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewValidatorManager(t *testing.T) {
	m := NewValidatorManager()
	require.NotNil(t, m)
	assert.Equal(t, 0, m.Count())
}

func TestValidatorManager_AddValidator(t *testing.T) {
	m := NewValidatorManager()

	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	operator := common.HexToAddress("0x2222222222222222222222222222222222222222")
	blsKey := make([]byte, 48)

	err := m.AddValidator(addr, operator, blsKey)
	require.NoError(t, err)

	assert.Equal(t, 1, m.Count())

	v, exists := m.GetValidator(addr)
	require.True(t, exists)
	assert.Equal(t, addr, v.Address)
	assert.Equal(t, operator, v.Operator)
}

func TestValidatorManager_AddValidator_Duplicate(t *testing.T) {
	m := NewValidatorManager()

	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	operator := common.HexToAddress("0x2222222222222222222222222222222222222222")
	blsKey := make([]byte, 48)

	err := m.AddValidator(addr, operator, blsKey)
	require.NoError(t, err)

	// Try to add duplicate
	err = m.AddValidator(addr, operator, blsKey)
	assert.ErrorIs(t, err, ErrValidatorExists)
}

func TestValidatorManager_RemoveValidator(t *testing.T) {
	m := NewValidatorManager()

	addr1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	addr2 := common.HexToAddress("0x2222222222222222222222222222222222222222")
	operator := common.HexToAddress("0x3333333333333333333333333333333333333333")
	blsKey := make([]byte, 48)

	m.AddValidator(addr1, operator, blsKey)
	m.AddValidator(addr2, operator, blsKey)
	assert.Equal(t, 2, m.Count())

	err := m.RemoveValidator(addr1)
	require.NoError(t, err)

	assert.Equal(t, 1, m.Count())

	_, exists := m.GetValidator(addr1)
	assert.False(t, exists)

	_, exists = m.GetValidator(addr2)
	assert.True(t, exists)
}

func TestValidatorManager_RemoveValidator_NotFound(t *testing.T) {
	m := NewValidatorManager()

	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")

	err := m.RemoveValidator(addr)
	assert.ErrorIs(t, err, ErrValidatorNotFound)
}

func TestValidatorManager_GetValidators(t *testing.T) {
	m := NewValidatorManager()

	addr1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	addr2 := common.HexToAddress("0x2222222222222222222222222222222222222222")
	operator := common.HexToAddress("0x3333333333333333333333333333333333333333")
	blsKey := make([]byte, 48)

	m.AddValidator(addr1, operator, blsKey)
	m.AddValidator(addr2, operator, blsKey)

	validators := m.GetValidators()
	assert.Len(t, validators, 2)
}

func TestValidatorManager_GetValidatorAddresses(t *testing.T) {
	m := NewValidatorManager()

	addr1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	addr2 := common.HexToAddress("0x2222222222222222222222222222222222222222")
	operator := common.HexToAddress("0x3333333333333333333333333333333333333333")
	blsKey := make([]byte, 48)

	m.AddValidator(addr1, operator, blsKey)
	m.AddValidator(addr2, operator, blsKey)

	addrs := m.GetValidatorAddresses()
	assert.Len(t, addrs, 2)
	assert.Contains(t, addrs, addr1)
	assert.Contains(t, addrs, addr2)
}

func TestValidatorManager_GasTip(t *testing.T) {
	m := NewValidatorManager()

	// Initial gas tip is 0
	assert.Equal(t, big.NewInt(0), m.GetGasTip())

	// Set gas tip
	m.SetGasTip(big.NewInt(1000))
	assert.Equal(t, big.NewInt(1000), m.GetGasTip())
}

func TestValidatorManager_GetProposer(t *testing.T) {
	m := NewValidatorManager()

	addr1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	addr2 := common.HexToAddress("0x2222222222222222222222222222222222222222")
	addr3 := common.HexToAddress("0x3333333333333333333333333333333333333333")
	operator := common.HexToAddress("0x4444444444444444444444444444444444444444")
	blsKey := make([]byte, 48)

	m.AddValidator(addr1, operator, blsKey)
	m.AddValidator(addr2, operator, blsKey)
	m.AddValidator(addr3, operator, blsKey)

	// Round-robin selection
	proposer, err := m.GetProposer(0)
	require.NoError(t, err)
	assert.Equal(t, addr1, proposer)

	proposer, err = m.GetProposer(1)
	require.NoError(t, err)
	assert.Equal(t, addr2, proposer)

	proposer, err = m.GetProposer(2)
	require.NoError(t, err)
	assert.Equal(t, addr3, proposer)

	proposer, err = m.GetProposer(3)
	require.NoError(t, err)
	assert.Equal(t, addr1, proposer) // Wraps around
}

func TestValidatorManager_GetProposer_NoValidators(t *testing.T) {
	m := NewValidatorManager()

	_, err := m.GetProposer(0)
	assert.ErrorIs(t, err, ErrNoValidators)
}

func TestValidatorManager_Clear(t *testing.T) {
	m := NewValidatorManager()

	addr1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	addr2 := common.HexToAddress("0x2222222222222222222222222222222222222222")
	operator := common.HexToAddress("0x3333333333333333333333333333333333333333")
	blsKey := make([]byte, 48)

	m.AddValidator(addr1, operator, blsKey)
	m.AddValidator(addr2, operator, blsKey)
	assert.Equal(t, 2, m.Count())

	m.Clear()
	assert.Equal(t, 0, m.Count())
}

func TestCalculateMappingSlot(t *testing.T) {
	slot := common.HexToHash("0x35")
	key := common.HexToAddress("0x1111111111111111111111111111111111111111")

	result := CalculateMappingSlot(slot, key)
	assert.NotEqual(t, common.Hash{}, result)

	// Same inputs should produce same output
	result2 := CalculateMappingSlot(slot, key)
	assert.Equal(t, result, result2)
}

func TestCalculateDynamicSlot(t *testing.T) {
	baseSlot := common.HexToHash("0x33")
	index := big.NewInt(0)

	result := CalculateDynamicSlot(baseSlot, index)
	assert.NotEqual(t, common.Hash{}, result)

	// Different indices should produce different slots
	result2 := CalculateDynamicSlot(baseSlot, big.NewInt(1))
	assert.NotEqual(t, result, result2)
}
