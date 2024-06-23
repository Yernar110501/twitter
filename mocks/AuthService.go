// Code generated by mockery v2.43.2. DO NOT EDIT.

package mocks

import (
	context "context"

	twitter "github.com/Yernar110501/twitter"
	mock "github.com/stretchr/testify/mock"
)

// AuthService is an autogenerated mock type for the AuthService type
type AuthService struct {
	mock.Mock
}

// Register provides a mock function with given fields: ctx, input
func (_m *AuthService) Register(ctx context.Context, input twitter.RegisterInput) (twitter.AuthResponse, error) {
	ret := _m.Called(ctx, input)

	if len(ret) == 0 {
		panic("no return value specified for Register")
	}

	var r0 twitter.AuthResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, twitter.RegisterInput) (twitter.AuthResponse, error)); ok {
		return rf(ctx, input)
	}
	if rf, ok := ret.Get(0).(func(context.Context, twitter.RegisterInput) twitter.AuthResponse); ok {
		r0 = rf(ctx, input)
	} else {
		r0 = ret.Get(0).(twitter.AuthResponse)
	}

	if rf, ok := ret.Get(1).(func(context.Context, twitter.RegisterInput) error); ok {
		r1 = rf(ctx, input)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewAuthService creates a new instance of AuthService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewAuthService(t interface {
	mock.TestingT
	Cleanup(func())
}) *AuthService {
	mock := &AuthService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}