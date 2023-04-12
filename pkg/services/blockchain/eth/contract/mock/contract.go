// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/iden3/driver-did-iden3/pkg/services/blockchain/eth (interfaces: StateContract)

// Package mock_eth is a generated GoMock package.
package mock_eth

import (
	big "math/big"
	reflect "reflect"

	bind "github.com/ethereum/go-ethereum/accounts/abi/bind"
	gomock "github.com/golang/mock/gomock"
	abi "github.com/iden3/contracts-abi/state/go/abi"
)

// MockStateContract is a mock of StateContract interface.
type MockStateContract struct {
	ctrl     *gomock.Controller
	recorder *MockStateContractMockRecorder
}

// MockStateContractMockRecorder is the mock recorder for MockStateContract.
type MockStateContractMockRecorder struct {
	mock *MockStateContract
}

// NewMockStateContract creates a new mock instance.
func NewMockStateContract(ctrl *gomock.Controller) *MockStateContract {
	mock := &MockStateContract{ctrl: ctrl}
	mock.recorder = &MockStateContractMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockStateContract) EXPECT() *MockStateContractMockRecorder {
	return m.recorder
}

// GetGISTProofByRoot mocks base method.
func (m *MockStateContract) GetGISTProofByRoot(arg0 *bind.CallOpts, arg1, arg2 *big.Int) (abi.IStateGistProof, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetGISTProofByRoot", arg0, arg1, arg2)
	ret0, _ := ret[0].(abi.IStateGistProof)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetGISTProofByRoot indicates an expected call of GetGISTProofByRoot.
func (mr *MockStateContractMockRecorder) GetGISTProofByRoot(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetGISTProofByRoot", reflect.TypeOf((*MockStateContract)(nil).GetGISTProofByRoot), arg0, arg1, arg2)
}

// GetGISTRoot mocks base method.
func (m *MockStateContract) GetGISTRoot(arg0 *bind.CallOpts) (*big.Int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetGISTRoot", arg0)
	ret0, _ := ret[0].(*big.Int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetGISTRoot indicates an expected call of GetGISTRoot.
func (mr *MockStateContractMockRecorder) GetGISTRoot(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetGISTRoot", reflect.TypeOf((*MockStateContract)(nil).GetGISTRoot), arg0)
}

// GetGISTRootInfo mocks base method.
func (m *MockStateContract) GetGISTRootInfo(arg0 *bind.CallOpts, arg1 *big.Int) (abi.IStateGistRootInfo, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetGISTRootInfo", arg0, arg1)
	ret0, _ := ret[0].(abi.IStateGistRootInfo)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetGISTRootInfo indicates an expected call of GetGISTRootInfo.
func (mr *MockStateContractMockRecorder) GetGISTRootInfo(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetGISTRootInfo", reflect.TypeOf((*MockStateContract)(nil).GetGISTRootInfo), arg0, arg1)
}

// GetStateInfoById mocks base method.
func (m *MockStateContract) GetStateInfoById(arg0 *bind.CallOpts, arg1 *big.Int) (abi.IStateStateInfo, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetStateInfoById", arg0, arg1)
	ret0, _ := ret[0].(abi.IStateStateInfo)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetStateInfoById indicates an expected call of GetStateInfoById.
func (mr *MockStateContractMockRecorder) GetStateInfoById(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetStateInfoById", reflect.TypeOf((*MockStateContract)(nil).GetStateInfoById), arg0, arg1)
}

// GetStateInfoByIdAndState mocks base method.
func (m *MockStateContract) GetStateInfoByIdAndState(arg0 *bind.CallOpts, arg1, arg2 *big.Int) (abi.IStateStateInfo, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetStateInfoByIdAndState", arg0, arg1, arg2)
	ret0, _ := ret[0].(abi.IStateStateInfo)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetStateInfoByIdAndState indicates an expected call of GetStateInfoByIdAndState.
func (mr *MockStateContractMockRecorder) GetStateInfoByIdAndState(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetStateInfoByIdAndState", reflect.TypeOf((*MockStateContract)(nil).GetStateInfoByIdAndState), arg0, arg1, arg2)
}
