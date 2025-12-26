package stablenet

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stable-net/anvil-go/pkg/state"
)

// CoinConfig holds configuration for the native stablecoin.
type CoinConfig struct {
	Name         string
	Symbol       string
	Decimals     uint8
	Currency     string
	MasterMinter common.Address
	InitialSupply *big.Int
}

// DefaultCoinConfig returns the default stablecoin configuration.
func DefaultCoinConfig() *CoinConfig {
	return &CoinConfig{
		Name:          "StableNet USD",
		Symbol:        "SNUSD",
		Decimals:      6,
		Currency:      "USD",
		MasterMinter:  common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
		InitialSupply: big.NewInt(0),
	}
}

// GenesisConfig holds configuration for system contract genesis.
type GenesisConfig struct {
	Validators []Validator
	Coin       *CoinConfig
	GasTip     *big.Int
	Quorum     uint64
}

// DefaultGenesisConfig returns a default genesis configuration.
func DefaultGenesisConfig() *GenesisConfig {
	defaultValidator := common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
	return &GenesisConfig{
		Validators: []Validator{
			{
				Address:      defaultValidator,
				Operator:     defaultValidator,
				BLSPublicKey: make([]byte, 48), // Empty BLS key for testing
			},
		},
		Coin:   DefaultCoinConfig(),
		GasTip: big.NewInt(0),
		Quorum: 1,
	}
}

// InitializeSystemContracts sets up system contract state in the state manager.
func InitializeSystemContracts(sm *state.InMemoryManager, config *GenesisConfig) error {
	if config == nil {
		config = DefaultGenesisConfig()
	}

	// Initialize GovValidator contract
	if err := initGovValidator(sm, config); err != nil {
		return err
	}

	// Initialize NativeCoinAdapter contract
	if err := initNativeCoinAdapter(sm, config); err != nil {
		return err
	}

	// Initialize governance contracts
	if err := initGovMasterMinter(sm, config); err != nil {
		return err
	}

	if err := initGovMinter(sm, config); err != nil {
		return err
	}

	if err := initGovCouncil(sm, config); err != nil {
		return err
	}

	return nil
}

// initGovValidator initializes the GovValidator contract state.
func initGovValidator(sm *state.InMemoryManager, config *GenesisConfig) error {
	addr := GovValidatorAddress

	// Set BLS PoP precompile address
	sm.SetStorageAt(addr, common.HexToHash(SlotValidatorBLSPoP),
		common.BytesToHash(BLSPoPPrecompileAddress.Bytes()))

	// Set gas tip
	if config.GasTip != nil {
		sm.SetStorageAt(addr, common.HexToHash(SlotValidatorGasTip),
			common.BigToHash(config.GasTip))
	}

	// Set validators
	validatorsSlot := common.HexToHash(SlotValidatorValidators)
	numValidators := big.NewInt(int64(len(config.Validators)))
	sm.SetStorageAt(addr, validatorsSlot, common.BigToHash(numValidators))

	for i, v := range config.Validators {
		// Set validator at index
		elementSlot := CalculateDynamicSlot(validatorsSlot, big.NewInt(int64(i)))
		sm.SetStorageAt(addr, elementSlot, common.BytesToHash(v.Address.Bytes()))

		// Set validator to operator mapping
		v2oSlot := CalculateMappingSlot(common.HexToHash(SlotValidatorValidatorToOperator), v.Address)
		sm.SetStorageAt(addr, v2oSlot, common.BytesToHash(v.Operator.Bytes()))

		// Set operator to validator mapping
		o2vSlot := CalculateMappingSlot(common.HexToHash(SlotValidatorOperatorToValidator), v.Operator)
		sm.SetStorageAt(addr, o2vSlot, common.BytesToHash(v.Address.Bytes()))
	}

	// Initialize governance base (members)
	return initGovBase(sm, addr, config.Validators, config.Quorum)
}

// initGovBase initializes common governance contract state.
func initGovBase(sm *state.InMemoryManager, addr common.Address, validators []Validator, quorum uint64) error {
	// Set members (operators)
	membersSlot := common.HexToHash(SlotGovMembers)
	numMembers := big.NewInt(int64(len(validators)))
	sm.SetStorageAt(addr, membersSlot, common.BigToHash(numMembers))

	for i, v := range validators {
		elementSlot := CalculateDynamicSlot(membersSlot, big.NewInt(int64(i)))
		sm.SetStorageAt(addr, elementSlot, common.BytesToHash(v.Operator.Bytes()))
	}

	// Set quorum
	sm.SetStorageAt(addr, common.HexToHash(SlotGovQuorum),
		common.BigToHash(big.NewInt(int64(quorum))))

	// Set member version to 1
	sm.SetStorageAt(addr, common.HexToHash(SlotGovMemberVersion),
		common.BigToHash(big.NewInt(1)))

	return nil
}

// initNativeCoinAdapter initializes the NativeCoinAdapter contract state.
func initNativeCoinAdapter(sm *state.InMemoryManager, config *GenesisConfig) error {
	addr := NativeCoinAdapterAddress

	if config.Coin == nil {
		config.Coin = DefaultCoinConfig()
	}

	// Set master minter
	sm.SetStorageAt(addr, common.HexToHash(SlotCoinMasterMinter),
		common.BytesToHash(config.Coin.MasterMinter.Bytes()))

	// Set token metadata
	sm.SetStorageAt(addr, common.HexToHash(SlotCoinDecimals),
		common.BigToHash(big.NewInt(int64(config.Coin.Decimals))))

	// Set total supply
	if config.Coin.InitialSupply != nil {
		sm.SetStorageAt(addr, common.HexToHash(SlotCoinTotalSupply),
			common.BigToHash(config.Coin.InitialSupply))
	}

	return nil
}

// initGovMasterMinter initializes the GovMasterMinter contract state.
func initGovMasterMinter(sm *state.InMemoryManager, config *GenesisConfig) error {
	return initGovBase(sm, GovMasterMinterAddress, config.Validators, config.Quorum)
}

// initGovMinter initializes the GovMinter contract state.
func initGovMinter(sm *state.InMemoryManager, config *GenesisConfig) error {
	return initGovBase(sm, GovMinterAddress, config.Validators, config.Quorum)
}

// initGovCouncil initializes the GovCouncil contract state.
func initGovCouncil(sm *state.InMemoryManager, config *GenesisConfig) error {
	return initGovBase(sm, GovCouncilAddress, config.Validators, config.Quorum)
}
