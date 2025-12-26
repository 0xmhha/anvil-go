// Package genesis provides genesis block creation for the simulator.
package genesis

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/tyler-smith/go-bip39"

	"github.com/stable-net/anvil-go/pkg/config"
)

// System contract addresses (StableNet specific).
var (
	GovValidatorAddress      = common.HexToAddress("0x0000000000000000000000000000000000000100")
	GovMinterAddress         = common.HexToAddress("0x0000000000000000000000000000000000000101")
	GovMasterMinterAddress   = common.HexToAddress("0x0000000000000000000000000000000000000102")
	NativeCoinAdapterAddress = common.HexToAddress("0x0000000000000000000000000000000000000103")
)

// Account represents a test account with its private key.
type Account struct {
	Address    common.Address
	PrivateKey *ecdsa.PrivateKey
}

// GenerateAccounts generates deterministic accounts from a mnemonic.
func GenerateAccounts(mnemonic string, count int) ([]*Account, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, fmt.Errorf("invalid mnemonic")
	}

	seed := bip39.NewSeed(mnemonic, "")
	accounts := make([]*Account, count)

	for i := 0; i < count; i++ {
		// Derive key using BIP-44 path: m/44'/60'/0'/0/i
		key, err := deriveKey(seed, uint32(i))
		if err != nil {
			return nil, fmt.Errorf("failed to derive key %d: %w", i, err)
		}

		accounts[i] = &Account{
			Address:    crypto.PubkeyToAddress(key.PublicKey),
			PrivateKey: key,
		}
	}

	return accounts, nil
}

// deriveKey derives a private key from seed at the given index.
// Uses simplified derivation for testing purposes.
func deriveKey(seed []byte, index uint32) (*ecdsa.PrivateKey, error) {
	// For simplicity, we use a deterministic derivation
	// In production, use proper BIP-32/BIP-44 derivation

	// Create a unique seed for each index by hashing seed + index
	indexBytes := make([]byte, 4)
	indexBytes[0] = byte(index >> 24)
	indexBytes[1] = byte(index >> 16)
	indexBytes[2] = byte(index >> 8)
	indexBytes[3] = byte(index)

	combined := append(seed, indexBytes...)
	hash := crypto.Keccak256(combined)

	return crypto.ToECDSA(hash)
}

// CreateGenesis creates a genesis block with test accounts.
func CreateGenesis(cfg *config.Config) (*core.Genesis, []*Account, error) {
	// Generate test accounts
	accounts, err := GenerateAccounts(cfg.Mnemonic, cfg.AccountCount)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate accounts: %w", err)
	}

	// Create genesis allocation
	alloc := make(core.GenesisAlloc)

	// Add test accounts with balance
	for _, acc := range accounts {
		alloc[acc.Address] = core.GenesisAccount{
			Balance: new(big.Int).Set(cfg.DefaultBalance),
		}
	}

	// Add system contracts if StableNet is enabled
	if cfg.HasStableNet() && cfg.StableNet.DeploySystemContracts {
		addSystemContracts(alloc, cfg)
	}

	// Create chain config
	chainConfig := createChainConfig(cfg.ChainID)

	genesis := &core.Genesis{
		Config:     chainConfig,
		Nonce:      0,
		Timestamp:  0,
		GasLimit:   cfg.GasLimit,
		Difficulty: big.NewInt(0),
		Alloc:      alloc,
		// For PoA/PoS, we use 0 difficulty
		// ExtraData can be set for consensus-specific data
	}

	return genesis, accounts, nil
}

// createChainConfig creates a chain configuration for the simulator.
func createChainConfig(chainID uint64) *params.ChainConfig {
	return &params.ChainConfig{
		ChainID:             big.NewInt(int64(chainID)),
		HomesteadBlock:      big.NewInt(0),
		EIP150Block:         big.NewInt(0),
		EIP155Block:         big.NewInt(0),
		EIP158Block:         big.NewInt(0),
		ByzantiumBlock:      big.NewInt(0),
		ConstantinopleBlock: big.NewInt(0),
		PetersburgBlock:     big.NewInt(0),
		IstanbulBlock:       big.NewInt(0),
		MuirGlacierBlock:    big.NewInt(0),
		BerlinBlock:         big.NewInt(0),
		LondonBlock:         big.NewInt(0),
		ArrowGlacierBlock:   big.NewInt(0),
		GrayGlacierBlock:    big.NewInt(0),
		// Enable all EIPs from block 0
		TerminalTotalDifficulty:       big.NewInt(0),
		TerminalTotalDifficultyPassed: true,
		ShanghaiTime:                  new(uint64),
		CancunTime:                    new(uint64),
	}
}

// addSystemContracts adds StableNet system contracts to genesis allocation.
func addSystemContracts(alloc core.GenesisAlloc, cfg *config.Config) {
	// GovValidator - Validator governance contract
	alloc[GovValidatorAddress] = core.GenesisAccount{
		Code:    getGovValidatorCode(),
		Balance: big.NewInt(0),
		Storage: initGovValidatorStorage(cfg),
	}

	// GovMinter - Minter governance contract
	alloc[GovMinterAddress] = core.GenesisAccount{
		Code:    getGovMinterCode(),
		Balance: big.NewInt(0),
		Storage: initGovMinterStorage(cfg),
	}

	// GovMasterMinter - Master minter governance contract
	alloc[GovMasterMinterAddress] = core.GenesisAccount{
		Code:    getGovMasterMinterCode(),
		Balance: big.NewInt(0),
		Storage: initGovMasterMinterStorage(cfg),
	}
}

// Placeholder functions for system contract bytecode and storage.
// These will be replaced with actual compiled contract bytecode.

func getGovValidatorCode() []byte {
	// Minimal contract that just returns
	// PUSH1 0x00 PUSH1 0x00 RETURN
	return []byte{0x60, 0x00, 0x60, 0x00, 0xf3}
}

func getGovMinterCode() []byte {
	return []byte{0x60, 0x00, 0x60, 0x00, 0xf3}
}

func getGovMasterMinterCode() []byte {
	return []byte{0x60, 0x00, 0x60, 0x00, 0xf3}
}

func initGovValidatorStorage(cfg *config.Config) map[common.Hash]common.Hash {
	storage := make(map[common.Hash]common.Hash)

	// Initialize validator set if provided
	if cfg.StableNet != nil && len(cfg.StableNet.Validators) > 0 {
		// Slot 0: validator count
		count := len(cfg.StableNet.Validators)
		storage[common.Hash{}] = common.BigToHash(big.NewInt(int64(count)))

		// Store each validator address
		for i, validator := range cfg.StableNet.Validators {
			slot := common.BigToHash(big.NewInt(int64(i + 1)))
			storage[slot] = common.BytesToHash(validator.Bytes())
		}
	}

	return storage
}

func initGovMinterStorage(cfg *config.Config) map[common.Hash]common.Hash {
	return make(map[common.Hash]common.Hash)
}

func initGovMasterMinterStorage(cfg *config.Config) map[common.Hash]common.Hash {
	return make(map[common.Hash]common.Hash)
}

// CreateGenesisBlock creates and returns the genesis block.
func CreateGenesisBlock(cfg *config.Config) (*core.Genesis, []*Account, error) {
	return CreateGenesis(cfg)
}
