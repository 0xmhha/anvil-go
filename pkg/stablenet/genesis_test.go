package stablenet

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stable-net/anvil-go/pkg/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultCoinConfig(t *testing.T) {
	cfg := DefaultCoinConfig()
	require.NotNil(t, cfg)

	assert.Equal(t, "StableNet USD", cfg.Name)
	assert.Equal(t, "SNUSD", cfg.Symbol)
	assert.Equal(t, uint8(6), cfg.Decimals)
	assert.Equal(t, "USD", cfg.Currency)
	assert.NotEqual(t, common.Address{}, cfg.MasterMinter)
}

func TestDefaultGenesisConfig(t *testing.T) {
	cfg := DefaultGenesisConfig()
	require.NotNil(t, cfg)

	assert.Len(t, cfg.Validators, 1)
	assert.NotNil(t, cfg.Coin)
	assert.NotNil(t, cfg.GasTip)
	assert.Equal(t, uint64(1), cfg.Quorum)
}

func TestInitializeSystemContracts(t *testing.T) {
	sm := state.NewInMemoryManager()
	cfg := DefaultGenesisConfig()

	err := InitializeSystemContracts(sm, cfg)
	require.NoError(t, err)

	// Verify GovValidator state
	blsPoPValue := sm.GetStorageAt(GovValidatorAddress, common.HexToHash(SlotValidatorBLSPoP))
	assert.Equal(t, common.BytesToHash(BLSPoPPrecompileAddress.Bytes()), blsPoPValue)

	// Verify validators array length
	validatorsLen := sm.GetStorageAt(GovValidatorAddress, common.HexToHash(SlotValidatorValidators))
	assert.Equal(t, common.BigToHash(big.NewInt(1)), validatorsLen)

	// Verify NativeCoinAdapter state
	decimals := sm.GetStorageAt(NativeCoinAdapterAddress, common.HexToHash(SlotCoinDecimals))
	assert.Equal(t, common.BigToHash(big.NewInt(6)), decimals)
}

func TestInitializeSystemContracts_NilConfig(t *testing.T) {
	sm := state.NewInMemoryManager()

	err := InitializeSystemContracts(sm, nil)
	require.NoError(t, err)

	// Should use defaults
	blsPoPValue := sm.GetStorageAt(GovValidatorAddress, common.HexToHash(SlotValidatorBLSPoP))
	assert.Equal(t, common.BytesToHash(BLSPoPPrecompileAddress.Bytes()), blsPoPValue)
}

func TestInitializeSystemContracts_MultipleValidators(t *testing.T) {
	sm := state.NewInMemoryManager()

	val1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	val2 := common.HexToAddress("0x2222222222222222222222222222222222222222")
	op1 := common.HexToAddress("0x3333333333333333333333333333333333333333")
	op2 := common.HexToAddress("0x4444444444444444444444444444444444444444")

	cfg := &GenesisConfig{
		Validators: []Validator{
			{Address: val1, Operator: op1, BLSPublicKey: make([]byte, 48)},
			{Address: val2, Operator: op2, BLSPublicKey: make([]byte, 48)},
		},
		Coin:   DefaultCoinConfig(),
		GasTip: big.NewInt(0),
		Quorum: 2,
	}

	err := InitializeSystemContracts(sm, cfg)
	require.NoError(t, err)

	// Verify validators array length
	validatorsLen := sm.GetStorageAt(GovValidatorAddress, common.HexToHash(SlotValidatorValidators))
	assert.Equal(t, common.BigToHash(big.NewInt(2)), validatorsLen)

	// Verify validator to operator mapping
	v2oSlot := CalculateMappingSlot(common.HexToHash(SlotValidatorValidatorToOperator), val1)
	op1Value := sm.GetStorageAt(GovValidatorAddress, v2oSlot)
	assert.Equal(t, common.BytesToHash(op1.Bytes()), op1Value)

	// Verify operator to validator mapping
	o2vSlot := CalculateMappingSlot(common.HexToHash(SlotValidatorOperatorToValidator), op1)
	val1Value := sm.GetStorageAt(GovValidatorAddress, o2vSlot)
	assert.Equal(t, common.BytesToHash(val1.Bytes()), val1Value)
}

func TestInitializeSystemContracts_CustomGasTip(t *testing.T) {
	sm := state.NewInMemoryManager()

	cfg := DefaultGenesisConfig()
	cfg.GasTip = big.NewInt(1e9) // 1 gwei

	err := InitializeSystemContracts(sm, cfg)
	require.NoError(t, err)

	gasTipValue := sm.GetStorageAt(GovValidatorAddress, common.HexToHash(SlotValidatorGasTip))
	assert.Equal(t, common.BigToHash(big.NewInt(1e9)), gasTipValue)
}

func TestInitializeSystemContracts_CustomCoin(t *testing.T) {
	sm := state.NewInMemoryManager()

	cfg := DefaultGenesisConfig()
	cfg.Coin = &CoinConfig{
		Name:          "Test Coin",
		Symbol:        "TEST",
		Decimals:      18,
		Currency:      "TST",
		MasterMinter:  common.HexToAddress("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
		InitialSupply: big.NewInt(1000000),
	}

	err := InitializeSystemContracts(sm, cfg)
	require.NoError(t, err)

	// Verify decimals
	decimals := sm.GetStorageAt(NativeCoinAdapterAddress, common.HexToHash(SlotCoinDecimals))
	assert.Equal(t, common.BigToHash(big.NewInt(18)), decimals)

	// Verify total supply
	supply := sm.GetStorageAt(NativeCoinAdapterAddress, common.HexToHash(SlotCoinTotalSupply))
	assert.Equal(t, common.BigToHash(big.NewInt(1000000)), supply)

	// Verify master minter
	masterMinter := sm.GetStorageAt(NativeCoinAdapterAddress, common.HexToHash(SlotCoinMasterMinter))
	assert.Equal(t, common.BytesToHash(cfg.Coin.MasterMinter.Bytes()), masterMinter)
}

func TestGovernanceContractsInitialized(t *testing.T) {
	sm := state.NewInMemoryManager()

	cfg := DefaultGenesisConfig()
	err := InitializeSystemContracts(sm, cfg)
	require.NoError(t, err)

	// All governance contracts should have members initialized
	govContracts := []common.Address{
		GovValidatorAddress,
		GovMasterMinterAddress,
		GovMinterAddress,
		GovCouncilAddress,
	}

	for _, addr := range govContracts {
		// Verify members array length
		membersLen := sm.GetStorageAt(addr, common.HexToHash(SlotGovMembers))
		assert.Equal(t, common.BigToHash(big.NewInt(1)), membersLen,
			"Expected 1 member for contract %s", addr.Hex())

		// Verify quorum
		quorum := sm.GetStorageAt(addr, common.HexToHash(SlotGovQuorum))
		assert.Equal(t, common.BigToHash(big.NewInt(1)), quorum,
			"Expected quorum 1 for contract %s", addr.Hex())

		// Verify member version
		version := sm.GetStorageAt(addr, common.HexToHash(SlotGovMemberVersion))
		assert.Equal(t, common.BigToHash(big.NewInt(1)), version,
			"Expected version 1 for contract %s", addr.Hex())
	}
}
