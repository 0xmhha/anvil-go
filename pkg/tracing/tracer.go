// Package tracing provides EVM execution tracing capabilities.
package tracing

import (
	"encoding/json"
	"math/big"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/vm"
)

// CallLog represents an event log emitted during execution.
type CallLog struct {
	Address  common.Address `json:"address"`
	Topics   []common.Hash  `json:"topics"`
	Data     hexutil.Bytes  `json:"data"`
	Position uint           `json:"position"`
}

// CallFrame represents a single call frame in the execution trace.
type CallFrame struct {
	Type         string          `json:"type"`
	From         common.Address  `json:"from"`
	To           *common.Address `json:"to,omitempty"`
	Value        *hexutil.Big    `json:"value,omitempty"`
	Gas          hexutil.Uint64  `json:"gas"`
	GasUsed      hexutil.Uint64  `json:"gasUsed"`
	Input        hexutil.Bytes   `json:"input,omitempty"`
	Output       hexutil.Bytes   `json:"output,omitempty"`
	Error        string          `json:"error,omitempty"`
	RevertReason string          `json:"revertReason,omitempty"`
	Calls        []CallFrame     `json:"calls,omitempty"`
	Logs         []CallLog       `json:"logs,omitempty"`
}

// internalFrame is used internally during tracing.
type internalFrame struct {
	typ     vm.OpCode
	from    common.Address
	to      *common.Address
	value   *big.Int
	gas     uint64
	gasUsed uint64
	input   []byte
	output  []byte
	err     error
	calls   []internalFrame
	logs    []CallLog
}

func (f *internalFrame) toCallFrame() CallFrame {
	cf := CallFrame{
		Type:    f.typ.String(),
		From:    f.from,
		To:      f.to,
		Gas:     hexutil.Uint64(f.gas),
		GasUsed: hexutil.Uint64(f.gasUsed),
	}

	if f.value != nil && f.value.Sign() > 0 {
		cf.Value = (*hexutil.Big)(f.value)
	}

	if len(f.input) > 0 {
		cf.Input = f.input
	}

	if len(f.output) > 0 {
		cf.Output = f.output
	}

	if f.err != nil {
		cf.Error = f.err.Error()
	}

	if len(f.calls) > 0 {
		cf.Calls = make([]CallFrame, len(f.calls))
		for i, c := range f.calls {
			cf.Calls[i] = c.toCallFrame()
		}
	}

	if len(f.logs) > 0 {
		cf.Logs = f.logs
	}

	return cf
}

// CallTracerConfig configures the call tracer.
type CallTracerConfig struct {
	OnlyTopCall bool `json:"onlyTopCall"`
	WithLog     bool `json:"withLog"`
}

// CallTracer traces call frames during EVM execution.
type CallTracer struct {
	callstack []internalFrame
	config    CallTracerConfig
	gasLimit  uint64
	depth     int
	interrupt atomic.Bool
	reason    error
}

// NewCallTracer creates a new call tracer.
func NewCallTracer(cfg *CallTracerConfig) *CallTracer {
	config := CallTracerConfig{}
	if cfg != nil {
		config = *cfg
	}
	return &CallTracer{
		callstack: make([]internalFrame, 1),
		config:    config,
	}
}

// CaptureStart implements vm.EVMLogger.
func (t *CallTracer) CaptureStart(env *vm.EVM, from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int) {
	toCopy := to
	typ := vm.CALL
	if create {
		typ = vm.CREATE
	}

	t.callstack[0] = internalFrame{
		typ:   typ,
		from:  from,
		to:    &toCopy,
		input: common.CopyBytes(input),
		gas:   t.gasLimit,
		value: value,
	}
	t.depth = 1
}

// CaptureEnd implements vm.EVMLogger.
func (t *CallTracer) CaptureEnd(output []byte, gasUsed uint64, err error) {
	t.callstack[0].output = common.CopyBytes(output)
	t.callstack[0].gasUsed = gasUsed
	t.callstack[0].err = err
}

// CaptureState implements vm.EVMLogger.
func (t *CallTracer) CaptureState(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, rData []byte, depth int, err error) {
	// Skip if error or not logging
	if err != nil || !t.config.WithLog {
		return
	}

	if t.config.OnlyTopCall && depth > 1 {
		return
	}

	if t.interrupt.Load() {
		return
	}

	// Handle LOG opcodes
	switch op {
	case vm.LOG0, vm.LOG1, vm.LOG2, vm.LOG3, vm.LOG4:
		size := int(op - vm.LOG0)
		stack := scope.Stack
		stackData := stack.Data()

		if len(stackData) < 2+size {
			return
		}

		mStart := stackData[len(stackData)-1].Uint64()
		mSize := stackData[len(stackData)-2].Uint64()

		topics := make([]common.Hash, size)
		for i := 0; i < size; i++ {
			topic := stackData[len(stackData)-2-(i+1)]
			topics[i] = common.Hash(topic.Bytes32())
		}

		data := make([]byte, mSize)
		if mSize > 0 {
			copy(data, scope.Memory.GetCopy(int64(mStart), int64(mSize)))
		}

		log := CallLog{
			Address:  scope.Contract.Address(),
			Topics:   topics,
			Data:     data,
			Position: uint(len(t.callstack[len(t.callstack)-1].calls)),
		}
		t.callstack[len(t.callstack)-1].logs = append(t.callstack[len(t.callstack)-1].logs, log)
	}
}

// CaptureFault implements vm.EVMLogger.
func (t *CallTracer) CaptureFault(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, depth int, err error) {
}

// CaptureEnter implements vm.EVMLogger.
func (t *CallTracer) CaptureEnter(typ vm.OpCode, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	if t.config.OnlyTopCall {
		return
	}

	if t.interrupt.Load() {
		return
	}

	toCopy := to
	call := internalFrame{
		typ:   typ,
		from:  from,
		to:    &toCopy,
		input: common.CopyBytes(input),
		gas:   gas,
		value: value,
	}
	t.callstack = append(t.callstack, call)
	t.depth++
}

// CaptureExit implements vm.EVMLogger.
func (t *CallTracer) CaptureExit(output []byte, gasUsed uint64, err error) {
	if t.config.OnlyTopCall {
		return
	}

	size := len(t.callstack)
	if size <= 1 {
		return
	}

	// Pop call
	call := t.callstack[size-1]
	t.callstack = t.callstack[:size-1]
	size--

	call.gasUsed = gasUsed
	call.output = common.CopyBytes(output)
	call.err = err

	t.callstack[size-1].calls = append(t.callstack[size-1].calls, call)
	t.depth--
}

// CaptureTxStart implements vm.EVMLogger.
func (t *CallTracer) CaptureTxStart(gasLimit uint64) {
	t.gasLimit = gasLimit
}

// CaptureTxEnd implements vm.EVMLogger.
func (t *CallTracer) CaptureTxEnd(restGas uint64) {
	t.callstack[0].gasUsed = t.gasLimit - restGas
}

// GetResult returns the tracing result.
func (t *CallTracer) GetResult() (*CallFrame, error) {
	if len(t.callstack) == 0 {
		return nil, nil
	}

	result := t.callstack[0].toCallFrame()
	return &result, nil
}

// GetResultJSON returns the tracing result as JSON.
func (t *CallTracer) GetResultJSON() (json.RawMessage, error) {
	result, err := t.GetResult()
	if err != nil {
		return nil, err
	}
	return json.Marshal(result)
}

// Stop stops the tracer.
func (t *CallTracer) Stop(err error) {
	t.reason = err
	t.interrupt.Store(true)
}

// Reset resets the tracer for reuse.
func (t *CallTracer) Reset() {
	t.callstack = make([]internalFrame, 1)
	t.gasLimit = 0
	t.depth = 0
	t.interrupt.Store(false)
	t.reason = nil
}
