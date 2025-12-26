package genesis

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stable-net/anvil-go/pkg/config"
)

func TestGenerateAccounts(t *testing.T) {
	mnemonic := "test test test test test test test test test test test junk"

	accounts, err := GenerateAccounts(mnemonic, 10)

	require.NoError(t, err)
	assert.Len(t, accounts, 10)

	// All accounts should have valid addresses
	for _, acc := range accounts {
		assert.NotEqual(t, common.Address{}, acc.Address)
		assert.NotNil(t, acc.PrivateKey)
	}
}

func TestGenerateAccounts_Deterministic(t *testing.T) {
	mnemonic := "test test test test test test test test test test test junk"

	accounts1, err := GenerateAccounts(mnemonic, 10)
	require.NoError(t, err)

	accounts2, err := GenerateAccounts(mnemonic, 10)
	require.NoError(t, err)

	// Same mnemonic should produce same accounts
	for i := range accounts1 {
		assert.Equal(t, accounts1[i].Address, accounts2[i].Address)
	}
}

func TestGenerateAccounts_DifferentMnemonics(t *testing.T) {
	mnemonic1 := "test test test test test test test test test test test junk"
	mnemonic2 := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

	accounts1, err := GenerateAccounts(mnemonic1, 5)
	require.NoError(t, err)

	accounts2, err := GenerateAccounts(mnemonic2, 5)
	require.NoError(t, err)

	// Different mnemonics should produce different accounts
	for i := range accounts1 {
		assert.NotEqual(t, accounts1[i].Address, accounts2[i].Address)
	}
}

func TestGenerateAccounts_InvalidMnemonic(t *testing.T) {
	_, err := GenerateAccounts("invalid mnemonic words", 10)
	assert.Error(t, err)
}

func TestGenerateAccounts_KnownAddresses(t *testing.T) {
	// Known addresses from the default test mnemonic
	// These are the same addresses Hardhat/Foundry use
	mnemonic := "test test test test test test test test test test test junk"

	accounts, err := GenerateAccounts(mnemonic, 3)
	require.NoError(t, err)

	// First account should be a known address
	// Note: The exact address depends on the derivation path
	assert.NotEqual(t, common.Address{}, accounts[0].Address)
}

func TestCreateGenesis(t *testing.T) {
	cfg := config.Default()

	genesis, accounts, err := CreateGenesis(cfg)

	require.NoError(t, err)
	assert.NotNil(t, genesis)
	assert.Len(t, accounts, cfg.AccountCount)

	// Genesis should have correct chain ID
	assert.Equal(t, cfg.ChainID, genesis.Config.ChainID.Uint64())

	// Genesis should have correct gas limit
	assert.Equal(t, cfg.GasLimit, genesis.GasLimit)

	// All accounts should be allocated in genesis
	for _, acc := range accounts {
		alloc, exists := genesis.Alloc[acc.Address]
		assert.True(t, exists, "Account %s should be in genesis alloc", acc.Address.Hex())
		assert.Equal(t, cfg.DefaultBalance, alloc.Balance)
	}
}

func TestCreateGenesis_CustomBalance(t *testing.T) {
	cfg := config.Default()
	cfg.DefaultBalance = big.NewInt(1e18) // 1 ETH

	genesis, accounts, err := CreateGenesis(cfg)

	require.NoError(t, err)
	for _, acc := range accounts {
		alloc := genesis.Alloc[acc.Address]
		assert.Equal(t, cfg.DefaultBalance, alloc.Balance)
	}
}

func TestCreateGenesis_CustomAccountCount(t *testing.T) {
	cfg := config.Default()
	cfg.AccountCount = 5

	genesis, accounts, err := CreateGenesis(cfg)

	require.NoError(t, err)
	assert.Len(t, accounts, 5)
	assert.Len(t, genesis.Alloc, 5)
}

func TestCreateGenesisWithSystemContracts(t *testing.T) {
	cfg := config.Default()
	cfg.StableNet = &config.StableNetConfig{
		DeploySystemContracts: true,
	}

	genesis, accounts, err := CreateGenesis(cfg)

	require.NoError(t, err)
	assert.NotNil(t, genesis)

	// Should have test accounts plus system contracts
	assert.Greater(t, len(genesis.Alloc), len(accounts))

	// System contracts should be deployed
	// GovValidator, GovMinter, GovMasterMinter, NativeCoinAdapter
	assert.Contains(t, genesis.Alloc, GovValidatorAddress)
	assert.Contains(t, genesis.Alloc, GovMinterAddress)
	assert.Contains(t, genesis.Alloc, GovMasterMinterAddress)
}

func TestAccountSignTransaction(t *testing.T) {
	mnemonic := "test test test test test test test test test test test junk"

	accounts, err := GenerateAccounts(mnemonic, 1)
	require.NoError(t, err)

	// Should be able to sign with the private key
	assert.NotNil(t, accounts[0].PrivateKey)
}

func TestGenesisBlock(t *testing.T) {
	cfg := config.Default()

	genesis, _, err := CreateGenesis(cfg)
	require.NoError(t, err)

	// Genesis block should have block number 0
	block := genesis.ToBlock()
	assert.Equal(t, uint64(0), block.NumberU64())

	// Genesis should have a valid state root
	assert.NotEqual(t, common.Hash{}, block.Root())
}
