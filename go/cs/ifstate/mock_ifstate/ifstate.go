// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/scionproto/scion/go/cs/ifstate (interfaces: InterfaceStateSender,RevInserter)

// Package mock_ifstate is a generated GoMock package.
package mock_ifstate

import (
	context "context"
	gomock "github.com/golang/mock/gomock"
	ifstate "github.com/scionproto/scion/go/cs/ifstate"
	path_mgmt "github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	net "net"
	reflect "reflect"
)

// MockInterfaceStateSender is a mock of InterfaceStateSender interface
type MockInterfaceStateSender struct {
	ctrl     *gomock.Controller
	recorder *MockInterfaceStateSenderMockRecorder
}

// MockInterfaceStateSenderMockRecorder is the mock recorder for MockInterfaceStateSender
type MockInterfaceStateSenderMockRecorder struct {
	mock *MockInterfaceStateSender
}

// NewMockInterfaceStateSender creates a new mock instance
func NewMockInterfaceStateSender(ctrl *gomock.Controller) *MockInterfaceStateSender {
	mock := &MockInterfaceStateSender{ctrl: ctrl}
	mock.recorder = &MockInterfaceStateSenderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockInterfaceStateSender) EXPECT() *MockInterfaceStateSenderMockRecorder {
	return m.recorder
}

// SendStateUpdate mocks base method
func (m *MockInterfaceStateSender) SendStateUpdate(arg0 context.Context, arg1 []ifstate.InterfaceState, arg2 net.Addr) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendStateUpdate", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendStateUpdate indicates an expected call of SendStateUpdate
func (mr *MockInterfaceStateSenderMockRecorder) SendStateUpdate(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendStateUpdate", reflect.TypeOf((*MockInterfaceStateSender)(nil).SendStateUpdate), arg0, arg1, arg2)
}

// MockRevInserter is a mock of RevInserter interface
type MockRevInserter struct {
	ctrl     *gomock.Controller
	recorder *MockRevInserterMockRecorder
}

// MockRevInserterMockRecorder is the mock recorder for MockRevInserter
type MockRevInserterMockRecorder struct {
	mock *MockRevInserter
}

// NewMockRevInserter creates a new mock instance
func NewMockRevInserter(ctrl *gomock.Controller) *MockRevInserter {
	mock := &MockRevInserter{ctrl: ctrl}
	mock.recorder = &MockRevInserterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockRevInserter) EXPECT() *MockRevInserterMockRecorder {
	return m.recorder
}

// InsertRevocations mocks base method
func (m *MockRevInserter) InsertRevocations(arg0 context.Context, arg1 ...*path_mgmt.SignedRevInfo) error {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0}
	for _, a := range arg1 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "InsertRevocations", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// InsertRevocations indicates an expected call of InsertRevocations
func (mr *MockRevInserterMockRecorder) InsertRevocations(arg0 interface{}, arg1 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0}, arg1...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InsertRevocations", reflect.TypeOf((*MockRevInserter)(nil).InsertRevocations), varargs...)
}
