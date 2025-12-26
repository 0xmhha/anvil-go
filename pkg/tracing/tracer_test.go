package tracing

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCallTracer(t *testing.T) {
	tracer := NewCallTracer(nil)
	require.NotNil(t, tracer)
	assert.Len(t, tracer.callstack, 1)
}

func TestNewCallTracer_WithConfig(t *testing.T) {
	cfg := &CallTracerConfig{
		OnlyTopCall: true,
		WithLog:     true,
	}
	tracer := NewCallTracer(cfg)
	require.NotNil(t, tracer)
	assert.True(t, tracer.config.OnlyTopCall)
	assert.True(t, tracer.config.WithLog)
}

func TestCallTracer_CaptureStart(t *testing.T) {
	tracer := NewCallTracer(nil)

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	input := []byte{0x01, 0x02, 0x03}
	value := big.NewInt(1000)

	tracer.CaptureTxStart(100000)
	tracer.CaptureStart(nil, from, to, false, input, 100000, value)

	assert.Equal(t, from, tracer.callstack[0].from)
	assert.Equal(t, to, *tracer.callstack[0].to)
	assert.Equal(t, input, tracer.callstack[0].input)
	assert.Equal(t, value, tracer.callstack[0].value)
	assert.Equal(t, vm.CALL, tracer.callstack[0].typ)
}

func TestCallTracer_CaptureStart_Create(t *testing.T) {
	tracer := NewCallTracer(nil)

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")

	tracer.CaptureTxStart(100000)
	tracer.CaptureStart(nil, from, to, true, nil, 100000, nil)

	assert.Equal(t, vm.CREATE, tracer.callstack[0].typ)
}

func TestCallTracer_CaptureEnd(t *testing.T) {
	tracer := NewCallTracer(nil)

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	output := []byte{0xde, 0xad, 0xbe, 0xef}

	tracer.CaptureTxStart(100000)
	tracer.CaptureStart(nil, from, to, false, nil, 100000, nil)
	tracer.CaptureEnd(output, 50000, nil)

	assert.Equal(t, output, tracer.callstack[0].output)
	assert.Equal(t, uint64(50000), tracer.callstack[0].gasUsed)
	assert.Nil(t, tracer.callstack[0].err)
}

func TestCallTracer_CaptureEnterExit(t *testing.T) {
	tracer := NewCallTracer(nil)

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	innerTo := common.HexToAddress("0x3333333333333333333333333333333333333333")

	tracer.CaptureTxStart(100000)
	tracer.CaptureStart(nil, from, to, false, nil, 100000, nil)

	// Enter inner call
	tracer.CaptureEnter(vm.CALL, to, innerTo, []byte{0x01}, 50000, big.NewInt(500))
	assert.Len(t, tracer.callstack, 2)
	assert.Equal(t, 2, tracer.depth)

	// Exit inner call
	tracer.CaptureExit([]byte{0x02}, 10000, nil)
	assert.Len(t, tracer.callstack, 1)
	assert.Equal(t, 1, tracer.depth)

	// Check inner call was added to parent
	assert.Len(t, tracer.callstack[0].calls, 1)
	assert.Equal(t, innerTo, *tracer.callstack[0].calls[0].to)
}

func TestCallTracer_OnlyTopCall(t *testing.T) {
	cfg := &CallTracerConfig{OnlyTopCall: true}
	tracer := NewCallTracer(cfg)

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	innerTo := common.HexToAddress("0x3333333333333333333333333333333333333333")

	tracer.CaptureTxStart(100000)
	tracer.CaptureStart(nil, from, to, false, nil, 100000, nil)

	// Enter inner call - should be ignored
	tracer.CaptureEnter(vm.CALL, to, innerTo, nil, 50000, nil)
	assert.Len(t, tracer.callstack, 1)

	// Exit inner call - should be ignored
	tracer.CaptureExit(nil, 10000, nil)
	assert.Len(t, tracer.callstack, 1)
}

func TestCallTracer_GetResult(t *testing.T) {
	tracer := NewCallTracer(nil)

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	input := []byte{0x01, 0x02}
	output := []byte{0xde, 0xad}
	value := big.NewInt(1000)

	tracer.CaptureTxStart(100000)
	tracer.CaptureStart(nil, from, to, false, input, 100000, value)
	tracer.CaptureEnd(output, 50000, nil)
	tracer.CaptureTxEnd(50000)

	result, err := tracer.GetResult()
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "CALL", result.Type)
	assert.Equal(t, from, result.From)
	assert.Equal(t, to, *result.To)
	assert.Equal(t, input, []byte(result.Input))
	assert.Equal(t, output, []byte(result.Output))
	assert.Equal(t, uint64(50000), uint64(result.GasUsed))
}

func TestCallTracer_GetResultJSON(t *testing.T) {
	tracer := NewCallTracer(nil)

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")

	tracer.CaptureTxStart(100000)
	tracer.CaptureStart(nil, from, to, false, nil, 100000, nil)
	tracer.CaptureEnd(nil, 21000, nil)
	tracer.CaptureTxEnd(79000)

	jsonResult, err := tracer.GetResultJSON()
	require.NoError(t, err)
	require.NotNil(t, jsonResult)

	var result CallFrame
	err = json.Unmarshal(jsonResult, &result)
	require.NoError(t, err)
	assert.Equal(t, "CALL", result.Type)
	assert.Equal(t, from, result.From)
}

func TestCallTracer_NestedCalls(t *testing.T) {
	tracer := NewCallTracer(nil)

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	inner1 := common.HexToAddress("0x3333333333333333333333333333333333333333")
	inner2 := common.HexToAddress("0x4444444444444444444444444444444444444444")

	tracer.CaptureTxStart(100000)
	tracer.CaptureStart(nil, from, to, false, nil, 100000, nil)

	// First inner call
	tracer.CaptureEnter(vm.CALL, to, inner1, nil, 50000, nil)
	// Nested call
	tracer.CaptureEnter(vm.STATICCALL, inner1, inner2, nil, 25000, nil)
	tracer.CaptureExit(nil, 5000, nil)
	tracer.CaptureExit(nil, 20000, nil)

	// Second inner call (sibling)
	tracer.CaptureEnter(vm.DELEGATECALL, to, inner1, nil, 30000, nil)
	tracer.CaptureExit(nil, 10000, nil)

	tracer.CaptureEnd(nil, 60000, nil)

	result, err := tracer.GetResult()
	require.NoError(t, err)

	// Should have 2 top-level calls
	assert.Len(t, result.Calls, 2)
	// First call should have 1 nested call
	assert.Len(t, result.Calls[0].Calls, 1)
	assert.Equal(t, "STATICCALL", result.Calls[0].Calls[0].Type)
}

func TestCallTracer_Stop(t *testing.T) {
	tracer := NewCallTracer(nil)

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")

	tracer.CaptureTxStart(100000)
	tracer.CaptureStart(nil, from, to, false, nil, 100000, nil)

	// Stop tracer
	tracer.Stop(nil)

	// Further captures should be ignored
	innerTo := common.HexToAddress("0x3333333333333333333333333333333333333333")
	tracer.CaptureEnter(vm.CALL, to, innerTo, nil, 50000, nil)

	// Should still only have 1 call in stack
	assert.Len(t, tracer.callstack, 1)
}

func TestCallTracer_Reset(t *testing.T) {
	tracer := NewCallTracer(nil)

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")

	tracer.CaptureTxStart(100000)
	tracer.CaptureStart(nil, from, to, false, nil, 100000, nil)
	tracer.CaptureEnd(nil, 21000, nil)

	tracer.Reset()

	assert.Len(t, tracer.callstack, 1)
	assert.Equal(t, uint64(0), tracer.gasLimit)
	assert.Equal(t, 0, tracer.depth)
}

func TestCallFrame_ToJSON(t *testing.T) {
	frame := CallFrame{
		Type: "CALL",
		From: common.HexToAddress("0x1111111111111111111111111111111111111111"),
		To: func() *common.Address {
			a := common.HexToAddress("0x2222222222222222222222222222222222222222")
			return &a
		}(),
		Gas:     100000,
		GasUsed: 21000,
		Input:   []byte{0x01, 0x02},
		Output:  []byte{0xde, 0xad},
	}

	data, err := json.Marshal(frame)
	require.NoError(t, err)

	var decoded CallFrame
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, frame.Type, decoded.Type)
	assert.Equal(t, frame.From, decoded.From)
	assert.Equal(t, *frame.To, *decoded.To)
	assert.Equal(t, frame.Gas, decoded.Gas)
	assert.Equal(t, frame.GasUsed, decoded.GasUsed)
}

func TestCallTracer_Error(t *testing.T) {
	tracer := NewCallTracer(nil)

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")

	tracer.CaptureTxStart(100000)
	tracer.CaptureStart(nil, from, to, false, nil, 100000, nil)
	tracer.CaptureEnd(nil, 21000, vm.ErrOutOfGas)

	result, err := tracer.GetResult()
	require.NoError(t, err)
	assert.Equal(t, "out of gas", result.Error)
}
