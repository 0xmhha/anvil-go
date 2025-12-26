package config

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := Default()

	assert.Equal(t, uint64(31337), cfg.ChainID)
	assert.Equal(t, uint64(30000000), cfg.GasLimit)
	assert.Equal(t, "127.0.0.1", cfg.Host)
	assert.Equal(t, 8545, cfg.Port)
	assert.Equal(t, 10, cfg.AccountCount)
	assert.Equal(t, DefaultMnemonic, cfg.Mnemonic)
	assert.Equal(t, "m/44'/60'/0'/0/", cfg.DerivationPath)
	assert.Equal(t, "auto", cfg.MiningMode)
	assert.Equal(t, time.Duration(0), cfg.BlockTime)
	assert.Equal(t, "*", cfg.AllowOrigin)

	// Default balance should be 10000 ETH
	expectedBalance := new(big.Int).Mul(big.NewInt(10000), big.NewInt(1e18))
	assert.Equal(t, expectedBalance, cfg.DefaultBalance)
}

func TestConfigValidation_Valid(t *testing.T) {
	cfg := Default()
	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestConfigValidation_InvalidChainID(t *testing.T) {
	cfg := Default()
	cfg.ChainID = 0

	err := cfg.Validate()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "chainId")
}

func TestConfigValidation_InvalidPort(t *testing.T) {
	tests := []struct {
		name string
		port int
	}{
		{"negative", -1},
		{"zero", 0},
		{"too high", 65536},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Default()
			cfg.Port = tt.port

			err := cfg.Validate()

			assert.Error(t, err)
			assert.Contains(t, err.Error(), "port")
		})
	}
}

func TestConfigValidation_InvalidAccountCount(t *testing.T) {
	cfg := Default()
	cfg.AccountCount = 0

	err := cfg.Validate()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "accountCount")
}

func TestConfigValidation_InvalidMiningMode(t *testing.T) {
	cfg := Default()
	cfg.MiningMode = "invalid"

	err := cfg.Validate()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "miningMode")
}

func TestConfigValidation_InvalidMnemonic(t *testing.T) {
	cfg := Default()
	cfg.Mnemonic = "invalid mnemonic"

	err := cfg.Validate()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mnemonic")
}

func TestConfigValidation_InvalidGasLimit(t *testing.T) {
	cfg := Default()
	cfg.GasLimit = 0

	err := cfg.Validate()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "gasLimit")
}

func TestLoadFromFile(t *testing.T) {
	// Create temp config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")

	configJSON := `{
		"chainId": 12345,
		"port": 9999,
		"accountCount": 5,
		"miningMode": "manual"
	}`

	err := os.WriteFile(configPath, []byte(configJSON), 0644)
	require.NoError(t, err)

	cfg, err := LoadFromFile(configPath)

	require.NoError(t, err)
	assert.Equal(t, uint64(12345), cfg.ChainID)
	assert.Equal(t, 9999, cfg.Port)
	assert.Equal(t, 5, cfg.AccountCount)
	assert.Equal(t, "manual", cfg.MiningMode)
	// Defaults should be applied for missing fields
	assert.Equal(t, "127.0.0.1", cfg.Host)
}

func TestLoadFromFile_NotFound(t *testing.T) {
	_, err := LoadFromFile("/nonexistent/path/config.json")
	assert.Error(t, err)
}

func TestLoadFromFile_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")

	err := os.WriteFile(configPath, []byte("invalid json"), 0644)
	require.NoError(t, err)

	_, err = LoadFromFile(configPath)
	assert.Error(t, err)
}

func TestWithStableNet(t *testing.T) {
	cfg := Default()
	cfg.StableNet = &StableNetConfig{
		DeploySystemContracts: true,
		EnableWBFT:            true,
	}

	err := cfg.Validate()
	assert.NoError(t, err)
	assert.True(t, cfg.StableNet.DeploySystemContracts)
	assert.True(t, cfg.StableNet.EnableWBFT)
}

func TestWithFork(t *testing.T) {
	cfg := Default()
	cfg.Fork = &ForkConfig{
		URL:         "https://mainnet.infura.io/v3/xxx",
		BlockNumber: 1000000,
		RetryCount:  3,
		Timeout:     30 * time.Second,
	}

	err := cfg.Validate()
	assert.NoError(t, err)
	assert.Equal(t, "https://mainnet.infura.io/v3/xxx", cfg.Fork.URL)
	assert.Equal(t, uint64(1000000), cfg.Fork.BlockNumber)
}

func TestForkConfigValidation_InvalidURL(t *testing.T) {
	cfg := Default()
	cfg.Fork = &ForkConfig{
		URL: "", // empty URL
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "fork")
}

func TestConfigCopy(t *testing.T) {
	cfg := Default()
	cfg.ChainID = 12345

	copied := cfg.Copy()

	// Modify original
	cfg.ChainID = 99999

	// Copy should be unchanged
	assert.Equal(t, uint64(12345), copied.ChainID)
}

func TestMergeWithDefaults(t *testing.T) {
	partial := &Config{
		ChainID: 12345,
		Port:    9999,
	}

	merged := MergeWithDefaults(partial)

	assert.Equal(t, uint64(12345), merged.ChainID)
	assert.Equal(t, 9999, merged.Port)
	// Defaults applied
	assert.Equal(t, "127.0.0.1", merged.Host)
	assert.Equal(t, 10, merged.AccountCount)
	assert.NotNil(t, merged.DefaultBalance)
}
