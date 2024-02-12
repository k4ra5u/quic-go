// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/k4ra5u/quic-go (interfaces: TokenStore)
//
// Generated by this command:
//
//	mockgen -typed -package quic -self_package github.com/k4ra5u/quic-go -self_package github.com/k4ra5u/quic-go -destination mock_token_store_test.go github.com/k4ra5u/quic-go TokenStore
//
// Package quic is a generated GoMock package.
package quic

import (
	reflect "reflect"

	gomock "go.uber.org/mock/gomock"
)

// MockTokenStore is a mock of TokenStore interface.
type MockTokenStore struct {
	ctrl     *gomock.Controller
	recorder *MockTokenStoreMockRecorder
}

// MockTokenStoreMockRecorder is the mock recorder for MockTokenStore.
type MockTokenStoreMockRecorder struct {
	mock *MockTokenStore
}

// NewMockTokenStore creates a new mock instance.
func NewMockTokenStore(ctrl *gomock.Controller) *MockTokenStore {
	mock := &MockTokenStore{ctrl: ctrl}
	mock.recorder = &MockTokenStoreMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockTokenStore) EXPECT() *MockTokenStoreMockRecorder {
	return m.recorder
}

// Pop mocks base method.
func (m *MockTokenStore) Pop(arg0 string) *ClientToken {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Pop", arg0)
	ret0, _ := ret[0].(*ClientToken)
	return ret0
}

// Pop indicates an expected call of Pop.
func (mr *MockTokenStoreMockRecorder) Pop(arg0 any) *TokenStorePopCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Pop", reflect.TypeOf((*MockTokenStore)(nil).Pop), arg0)
	return &TokenStorePopCall{Call: call}
}

// TokenStorePopCall wrap *gomock.Call
type TokenStorePopCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *TokenStorePopCall) Return(arg0 *ClientToken) *TokenStorePopCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *TokenStorePopCall) Do(f func(string) *ClientToken) *TokenStorePopCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *TokenStorePopCall) DoAndReturn(f func(string) *ClientToken) *TokenStorePopCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Put mocks base method.
func (m *MockTokenStore) Put(arg0 string, arg1 *ClientToken) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Put", arg0, arg1)
}

// Put indicates an expected call of Put.
func (mr *MockTokenStoreMockRecorder) Put(arg0, arg1 any) *TokenStorePutCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Put", reflect.TypeOf((*MockTokenStore)(nil).Put), arg0, arg1)
	return &TokenStorePutCall{Call: call}
}

// TokenStorePutCall wrap *gomock.Call
type TokenStorePutCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *TokenStorePutCall) Return() *TokenStorePutCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *TokenStorePutCall) Do(f func(string, *ClientToken)) *TokenStorePutCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *TokenStorePutCall) DoAndReturn(f func(string, *ClientToken)) *TokenStorePutCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}
