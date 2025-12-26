// Package stablenet provides StableNet system contract integration for the simulator.
package stablenet

import (
	"github.com/ethereum/go-ethereum/common"
)

// System contract addresses (matching go-stablenet defaults).
var (
	NativeCoinAdapterAddress = common.HexToAddress("0x1000")
	GovValidatorAddress      = common.HexToAddress("0x1001")
	GovMasterMinterAddress   = common.HexToAddress("0x1002")
	GovMinterAddress         = common.HexToAddress("0x1003")
	GovCouncilAddress        = common.HexToAddress("0x1004")

	// BLS PoP Precompile address
	BLSPoPPrecompileAddress = common.HexToAddress("0x0000000000000000000000000000000000B00001")
)

// Contract names for reference.
const (
	ContractGovValidator      = "GovValidator"
	ContractNativeCoinAdapter = "NativeCoinAdapter"
	ContractGovMinter         = "GovMinter"
	ContractGovMasterMinter   = "GovMasterMinter"
	ContractGovCouncil        = "GovCouncil"
)

// Storage slots for GovValidator contract.
const (
	SlotValidatorBLSPoP              = "0x32"
	SlotValidatorValidators          = "0x33"
	SlotValidatorValidatorToOperator = "0x35"
	SlotValidatorOperatorToValidator = "0x36"
	SlotValidatorValidatorToBlsKey   = "0x37"
	SlotValidatorBlsKeyToValidator   = "0x38"
	SlotValidatorGasTip              = "0x39"
)

// Storage slots for NativeCoinAdapter contract.
const (
	SlotCoinMasterMinter   = "0x0"
	SlotCoinMinters        = "0x1"
	SlotCoinMinterAllowed  = "0x2"
	SlotCoinManager        = "0x6"
	SlotCoinAccountManager = "0x7"
	SlotCoinName           = "0x8"
	SlotCoinSymbol         = "0x9"
	SlotCoinDecimals       = "0xa"
	SlotCoinCurrency       = "0xb"
	SlotCoinTotalSupply    = "0xd"
)

// Storage slots for GovBase (shared by all governance contracts).
const (
	SlotGovMembers           = "0x0"
	SlotGovMemberVersion     = "0x2"
	SlotGovProposals         = "0x3"
	SlotGovActiveProposalIDs = "0x4"
	SlotGovQuorum            = "0x5"
	SlotGovProposalExpiry    = "0x6"
)

// SystemContractAddresses returns all system contract addresses.
func SystemContractAddresses() []common.Address {
	return []common.Address{
		NativeCoinAdapterAddress,
		GovValidatorAddress,
		GovMasterMinterAddress,
		GovMinterAddress,
		GovCouncilAddress,
	}
}

// IsSystemContract checks if an address is a system contract.
func IsSystemContract(addr common.Address) bool {
	for _, sysAddr := range SystemContractAddresses() {
		if addr == sysAddr {
			return true
		}
	}
	return false
}
