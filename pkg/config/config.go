// Package config provides configuration management for anvil-go.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/tyler-smith/go-bip39"
)

// Default values.
var (
	DefaultChainID        = uint64(31337)
	DefaultGasLimit       = uint64(30000000)
	DefaultHost           = "127.0.0.1"
	DefaultPort           = 8545
	DefaultAccountCount   = 10
	DefaultBalance        = new(big.Int).Mul(big.NewInt(10000), big.NewInt(1e18)) // 10000 ETH
	DefaultMnemonic       = "test test test test test test test test test test test junk"
	DefaultDerivationPath = "m/44'/60'/0'/0/"
	DefaultMiningMode     = "auto"
	DefaultBlockTime      = time.Duration(0)
	DefaultAllowOrigin    = "*"
)

// Valid mining modes.
var validMiningModes = map[string]bool{
	"auto":     true,
	"interval": true,
	"manual":   true,
}

// Config defines the simulator configuration.
type Config struct {
	// Network configuration
	ChainID  uint64   `json:"chainId"`
	GasLimit uint64   `json:"gasLimit"`
	GasPrice *big.Int `json:"gasPrice,omitempty"`
	BaseFee  *big.Int `json:"baseFee,omitempty"`

	// Server configuration
	Host string `json:"host"`
	Port int    `json:"port"`

	// Account configuration
	AccountCount   int      `json:"accountCount"`
	DefaultBalance *big.Int `json:"defaultBalance"`
	Mnemonic       string   `json:"mnemonic"`
	DerivationPath string   `json:"derivationPath"`

	// Mining configuration
	MiningMode string        `json:"miningMode"` // auto, interval, manual
	BlockTime  time.Duration `json:"blockTime"`

	// Feature flags
	AutoImpersonate bool   `json:"autoImpersonate"`
	AllowOrigin     string `json:"allowOrigin"`

	// Fork configuration (optional)
	Fork *ForkConfig `json:"fork,omitempty"`

	// StableNet configuration (optional)
	StableNet *StableNetConfig `json:"stablenet,omitempty"`
}

// ForkConfig defines fork mode configuration.
type ForkConfig struct {
	URL         string        `json:"url"`
	BlockNumber uint64        `json:"blockNumber,omitempty"` // 0 = latest
	RetryCount  int           `json:"retryCount"`
	Timeout     time.Duration `json:"timeout"`
}

// StableNetConfig defines StableNet-specific configuration.
type StableNetConfig struct {
	DeploySystemContracts bool             `json:"deploySystemContracts"`
	Validators            []common.Address `json:"validators,omitempty"`
	EnableWBFT            bool             `json:"enableWbft"`
}

// Default returns a configuration with default values.
func Default() *Config {
	return &Config{
		ChainID:        DefaultChainID,
		GasLimit:       DefaultGasLimit,
		Host:           DefaultHost,
		Port:           DefaultPort,
		AccountCount:   DefaultAccountCount,
		DefaultBalance: new(big.Int).Set(DefaultBalance),
		Mnemonic:       DefaultMnemonic,
		DerivationPath: DefaultDerivationPath,
		MiningMode:     DefaultMiningMode,
		BlockTime:      DefaultBlockTime,
		AllowOrigin:    DefaultAllowOrigin,
	}
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	var errs []string

	if c.ChainID == 0 {
		errs = append(errs, "chainId must be greater than 0")
	}

	if c.GasLimit == 0 {
		errs = append(errs, "gasLimit must be greater than 0")
	}

	if c.Port <= 0 || c.Port > 65535 {
		errs = append(errs, "port must be between 1 and 65535")
	}

	if c.AccountCount <= 0 {
		errs = append(errs, "accountCount must be greater than 0")
	}

	if !validMiningModes[c.MiningMode] {
		errs = append(errs, fmt.Sprintf("miningMode must be one of: auto, interval, manual"))
	}

	if c.Mnemonic != "" && !bip39.IsMnemonicValid(c.Mnemonic) {
		errs = append(errs, "mnemonic is invalid")
	}

	// Validate fork config if present
	if c.Fork != nil {
		if c.Fork.URL == "" {
			errs = append(errs, "fork URL cannot be empty when fork is configured")
		}
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}

	return nil
}

// LoadFromFile loads configuration from a JSON file.
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Merge with defaults
	merged := MergeWithDefaults(&cfg)

	return merged, nil
}

// MergeWithDefaults merges partial config with default values.
func MergeWithDefaults(partial *Config) *Config {
	def := Default()

	if partial.ChainID != 0 {
		def.ChainID = partial.ChainID
	}
	if partial.GasLimit != 0 {
		def.GasLimit = partial.GasLimit
	}
	if partial.GasPrice != nil {
		def.GasPrice = partial.GasPrice
	}
	if partial.BaseFee != nil {
		def.BaseFee = partial.BaseFee
	}
	if partial.Host != "" {
		def.Host = partial.Host
	}
	if partial.Port != 0 {
		def.Port = partial.Port
	}
	if partial.AccountCount != 0 {
		def.AccountCount = partial.AccountCount
	}
	if partial.DefaultBalance != nil {
		def.DefaultBalance = partial.DefaultBalance
	}
	if partial.Mnemonic != "" {
		def.Mnemonic = partial.Mnemonic
	}
	if partial.DerivationPath != "" {
		def.DerivationPath = partial.DerivationPath
	}
	if partial.MiningMode != "" {
		def.MiningMode = partial.MiningMode
	}
	if partial.BlockTime != 0 {
		def.BlockTime = partial.BlockTime
	}
	if partial.AllowOrigin != "" {
		def.AllowOrigin = partial.AllowOrigin
	}
	def.AutoImpersonate = partial.AutoImpersonate
	def.Fork = partial.Fork
	def.StableNet = partial.StableNet

	return def
}

// Copy creates a deep copy of the configuration.
func (c *Config) Copy() *Config {
	copied := *c

	// Deep copy big.Int fields
	if c.DefaultBalance != nil {
		copied.DefaultBalance = new(big.Int).Set(c.DefaultBalance)
	}
	if c.GasPrice != nil {
		copied.GasPrice = new(big.Int).Set(c.GasPrice)
	}
	if c.BaseFee != nil {
		copied.BaseFee = new(big.Int).Set(c.BaseFee)
	}

	// Deep copy nested structs
	if c.Fork != nil {
		forkCopy := *c.Fork
		copied.Fork = &forkCopy
	}
	if c.StableNet != nil {
		stableNetCopy := *c.StableNet
		if c.StableNet.Validators != nil {
			stableNetCopy.Validators = make([]common.Address, len(c.StableNet.Validators))
			copy(stableNetCopy.Validators, c.StableNet.Validators)
		}
		copied.StableNet = &stableNetCopy
	}

	return &copied
}

// ServerAddr returns the server address string.
func (c *Config) ServerAddr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// IsAutomine returns true if auto-mining is enabled.
func (c *Config) IsAutomine() bool {
	return c.MiningMode == "auto"
}

// IsIntervalMining returns true if interval mining is enabled.
func (c *Config) IsIntervalMining() bool {
	return c.MiningMode == "interval"
}

// IsManualMining returns true if manual mining is enabled.
func (c *Config) IsManualMining() bool {
	return c.MiningMode == "manual"
}

// HasFork returns true if fork configuration is present.
func (c *Config) HasFork() bool {
	return c.Fork != nil && c.Fork.URL != ""
}

// HasStableNet returns true if StableNet configuration is present.
func (c *Config) HasStableNet() bool {
	return c.StableNet != nil
}
