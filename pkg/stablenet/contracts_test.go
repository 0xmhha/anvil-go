package stablenet

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
)

func TestSystemContractAddresses(t *testing.T) {
	addrs := SystemContractAddresses()
	assert.Len(t, addrs, 5)

	assert.Contains(t, addrs, NativeCoinAdapterAddress)
	assert.Contains(t, addrs, GovValidatorAddress)
	assert.Contains(t, addrs, GovMasterMinterAddress)
	assert.Contains(t, addrs, GovMinterAddress)
	assert.Contains(t, addrs, GovCouncilAddress)
}

func TestIsSystemContract(t *testing.T) {
	// System contracts
	assert.True(t, IsSystemContract(NativeCoinAdapterAddress))
	assert.True(t, IsSystemContract(GovValidatorAddress))
	assert.True(t, IsSystemContract(GovMasterMinterAddress))
	assert.True(t, IsSystemContract(GovMinterAddress))
	assert.True(t, IsSystemContract(GovCouncilAddress))

	// Non-system contracts
	assert.False(t, IsSystemContract(common.HexToAddress("0x1234567890123456789012345678901234567890")))
	assert.False(t, IsSystemContract(common.Address{}))
}

func TestContractAddressValues(t *testing.T) {
	// Verify addresses match go-stablenet defaults
	assert.Equal(t, common.HexToAddress("0x1000"), NativeCoinAdapterAddress)
	assert.Equal(t, common.HexToAddress("0x1001"), GovValidatorAddress)
	assert.Equal(t, common.HexToAddress("0x1002"), GovMasterMinterAddress)
	assert.Equal(t, common.HexToAddress("0x1003"), GovMinterAddress)
	assert.Equal(t, common.HexToAddress("0x1004"), GovCouncilAddress)
}

func TestBLSPoPPrecompileAddress(t *testing.T) {
	expected := common.HexToAddress("0x0000000000000000000000000000000000B00001")
	assert.Equal(t, expected, BLSPoPPrecompileAddress)
}
