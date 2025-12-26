package fork

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockRPCClient is a mock implementation of RPCClient for testing.
type mockRPCClient struct {
	responses map[string]interface{}
	closed    bool
}

func newMockRPCClient() *mockRPCClient {
	return &mockRPCClient{
		responses: make(map[string]interface{}),
	}
}

func (m *mockRPCClient) Call(ctx context.Context, result interface{}, method string, args ...interface{}) error {
	if m.closed {
		return errors.New("client closed")
	}

	resp, exists := m.responses[method]
	if !exists {
		return errors.New("method not found")
	}

	// Simple type assertion for test responses
	switch v := result.(type) {
	case *string:
		if s, ok := resp.(string); ok {
			*v = s
		}
	}

	return nil
}

func (m *mockRPCClient) Close() {
	m.closed = true
}

func (m *mockRPCClient) SetResponse(method string, response interface{}) {
	m.responses[method] = response
}

func TestNewProvider(t *testing.T) {
	config := &Config{
		URL: "http://localhost:8545",
	}
	provider := NewProvider(config)
	require.NotNil(t, provider)
	assert.Equal(t, "http://localhost:8545", provider.URL())
}

func TestNewProvider_NilConfig(t *testing.T) {
	provider := NewProvider(nil)
	require.NotNil(t, provider)
	assert.Equal(t, "", provider.URL())
}

func TestProvider_Connect_NoURL(t *testing.T) {
	provider := NewProvider(nil)
	err := provider.Connect(context.Background())
	assert.ErrorIs(t, err, ErrNoForkURL)
}

func TestProvider_Connect_NoClient(t *testing.T) {
	config := &Config{URL: "http://localhost:8545"}
	provider := NewProvider(config)
	err := provider.Connect(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestProvider_Connect_Success(t *testing.T) {
	config := &Config{URL: "http://localhost:8545"}
	provider := NewProvider(config)

	mockClient := newMockRPCClient()
	mockClient.SetResponse("eth_chainId", "0x1")
	mockClient.SetResponse("eth_blockNumber", "0x100")
	provider.SetClient(mockClient)

	err := provider.Connect(context.Background())
	require.NoError(t, err)

	assert.True(t, provider.IsConnected())
	assert.Equal(t, big.NewInt(1), provider.ChainID())
	assert.Equal(t, big.NewInt(256), provider.BlockNumber())
}

func TestProvider_Connect_WithChainID(t *testing.T) {
	config := &Config{
		URL:     "http://localhost:8545",
		ChainID: big.NewInt(31337),
	}
	provider := NewProvider(config)

	mockClient := newMockRPCClient()
	mockClient.SetResponse("eth_blockNumber", "0x100")
	provider.SetClient(mockClient)

	err := provider.Connect(context.Background())
	require.NoError(t, err)

	assert.Equal(t, big.NewInt(31337), provider.ChainID())
}

func TestProvider_Connect_WithBlockNumber(t *testing.T) {
	config := &Config{
		URL:         "http://localhost:8545",
		ChainID:     big.NewInt(1),
		BlockNumber: big.NewInt(15000000),
	}
	provider := NewProvider(config)

	mockClient := newMockRPCClient()
	provider.SetClient(mockClient)

	err := provider.Connect(context.Background())
	require.NoError(t, err)

	assert.Equal(t, big.NewInt(15000000), provider.BlockNumber())
}

func TestProvider_Disconnect(t *testing.T) {
	config := &Config{
		URL:     "http://localhost:8545",
		ChainID: big.NewInt(1),
	}
	provider := NewProvider(config)

	mockClient := newMockRPCClient()
	mockClient.SetResponse("eth_blockNumber", "0x100")
	provider.SetClient(mockClient)

	provider.Connect(context.Background())
	assert.True(t, provider.IsConnected())

	provider.Disconnect()
	assert.False(t, provider.IsConnected())
	assert.True(t, mockClient.closed)
}

func TestProvider_CachedBalance(t *testing.T) {
	provider := NewProvider(&Config{URL: "http://localhost:8545"})

	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	balance := big.NewInt(1000000)

	provider.SetCachedBalance(addr, balance)

	got, err := provider.GetBalance(context.Background(), addr)
	require.NoError(t, err)
	assert.Equal(t, balance, got)
}

func TestProvider_CachedNonce(t *testing.T) {
	provider := NewProvider(&Config{URL: "http://localhost:8545"})

	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")

	provider.SetCachedNonce(addr, 42)

	got, err := provider.GetNonce(context.Background(), addr)
	require.NoError(t, err)
	assert.Equal(t, uint64(42), got)
}

func TestProvider_CachedCode(t *testing.T) {
	provider := NewProvider(&Config{URL: "http://localhost:8545"})

	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	code := []byte{0x60, 0x00, 0x60, 0x00, 0xf3}

	provider.SetCachedCode(addr, code)

	got, err := provider.GetCode(context.Background(), addr)
	require.NoError(t, err)
	assert.Equal(t, code, got)
}

func TestProvider_CachedStorage(t *testing.T) {
	provider := NewProvider(&Config{URL: "http://localhost:8545"})

	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	slot := common.HexToHash("0x01")
	value := common.HexToHash("0x42")

	provider.SetCachedStorage(addr, slot, value)

	got, err := provider.GetStorageAt(context.Background(), addr, slot)
	require.NoError(t, err)
	assert.Equal(t, value, got)
}

func TestProvider_ClearCache(t *testing.T) {
	provider := NewProvider(&Config{URL: "http://localhost:8545"})

	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	provider.SetCachedBalance(addr, big.NewInt(1000))
	provider.SetCachedNonce(addr, 5)
	provider.SetCachedCode(addr, []byte{0x60})
	provider.SetCachedStorage(addr, common.Hash{}, common.Hash{})

	assert.Greater(t, provider.CacheSize(), 0)

	provider.ClearCache()

	assert.Equal(t, 0, provider.CacheSize())
}

func TestProvider_CacheSize(t *testing.T) {
	provider := NewProvider(&Config{URL: "http://localhost:8545"})

	assert.Equal(t, 0, provider.CacheSize())

	addr1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	addr2 := common.HexToAddress("0x2222222222222222222222222222222222222222")

	provider.SetCachedBalance(addr1, big.NewInt(1000))
	assert.Equal(t, 1, provider.CacheSize())

	provider.SetCachedNonce(addr2, 5)
	assert.Equal(t, 2, provider.CacheSize())

	provider.SetCachedCode(addr1, []byte{0x60})
	assert.Equal(t, 3, provider.CacheSize())

	provider.SetCachedStorage(addr1, common.Hash{}, common.Hash{})
	assert.Equal(t, 4, provider.CacheSize())
}

func TestProvider_GetBalance_NotConnected(t *testing.T) {
	provider := NewProvider(&Config{URL: "http://localhost:8545"})

	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")

	balance, err := provider.GetBalance(context.Background(), addr)
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(0), balance)
}

func TestProvider_GetNonce_NotConnected(t *testing.T) {
	provider := NewProvider(&Config{URL: "http://localhost:8545"})

	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")

	nonce, err := provider.GetNonce(context.Background(), addr)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), nonce)
}

func TestProvider_GetCode_NotConnected(t *testing.T) {
	provider := NewProvider(&Config{URL: "http://localhost:8545"})

	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")

	code, err := provider.GetCode(context.Background(), addr)
	require.NoError(t, err)
	assert.Nil(t, code)
}

func TestProvider_GetStorageAt_NotConnected(t *testing.T) {
	provider := NewProvider(&Config{URL: "http://localhost:8545"})

	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	slot := common.HexToHash("0x01")

	value, err := provider.GetStorageAt(context.Background(), addr, slot)
	require.NoError(t, err)
	assert.Equal(t, common.Hash{}, value)
}

func TestProvider_GetBlock_NotConnected(t *testing.T) {
	provider := NewProvider(&Config{URL: "http://localhost:8545"})

	block, err := provider.GetBlock(context.Background(), big.NewInt(1))
	assert.ErrorIs(t, err, ErrNotConnected)
	assert.Nil(t, block)
}

func TestProvider_ChainID_Nil(t *testing.T) {
	provider := NewProvider(&Config{URL: "http://localhost:8545"})
	assert.Nil(t, provider.ChainID())
}

func TestProvider_BlockNumber_Nil(t *testing.T) {
	provider := NewProvider(&Config{URL: "http://localhost:8545"})
	assert.Nil(t, provider.BlockNumber())
}
