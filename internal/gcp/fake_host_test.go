// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"unsafe"

	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	"github.com/oakwood-commons/scafctl-plugin-sdk/plugin/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeHostService implements proto.HostServiceClient backed by an in-memory map.
type fakeHostService struct {
	mu               sync.Mutex
	secrets          map[string]string
	getSecretFunc    func(ctx context.Context, name string) error
	setSecretErr     error
	setSecretKeyErr  map[string]error
	setSecretFunc    func(ctx context.Context, name, value string) error
	deleteSecretFunc func(ctx context.Context, name string) error
	promptFunc       func(ctx context.Context, req *proto.PromptAuthResponseRequest) (string, error)
}

func newFakeHostService() *fakeHostService {
	return &fakeHostService{secrets: make(map[string]string)}
}

// newFakeHostClient creates an sdkplugin.HostServiceClient backed by the fake.
func newFakeHostClient(fake *fakeHostService) *sdkplugin.HostServiceClient {
	hc := &sdkplugin.HostServiceClient{}
	// Inject the fake proto client into the unexported "client" field.
	field := reflect.ValueOf(hc).Elem().FieldByName("client")
	ptr := unsafe.Pointer(field.UnsafeAddr()) //nolint:gosec // intentional: injecting fake into unexported field for testing
	*(*proto.HostServiceClient)(ptr) = fake
	return hc
}

func (f *fakeHostService) GetSecret(ctx context.Context, in *proto.GetSecretRequest, _ ...grpc.CallOption) (*proto.GetSecretResponse, error) {
	f.mu.Lock()
	fn := f.getSecretFunc
	f.mu.Unlock()
	if fn != nil {
		if err := fn(ctx, in.Name); err != nil {
			return nil, err
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.secrets[in.Name]
	return &proto.GetSecretResponse{Value: v, Found: ok}, nil
}

func (f *fakeHostService) SetSecret(ctx context.Context, in *proto.SetSecretRequest, _ ...grpc.CallOption) (*proto.SetSecretResponse, error) {
	f.mu.Lock()
	fn := f.setSecretFunc
	f.mu.Unlock()
	if fn != nil {
		if err := fn(ctx, in.Name, in.Value); err != nil {
			return nil, err
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.setSecretKeyErr != nil {
		if err, ok := f.setSecretKeyErr[in.Name]; ok && err != nil {
			return nil, err
		}
	}
	if f.setSecretErr != nil {
		return nil, f.setSecretErr
	}
	f.secrets[in.Name] = in.Value
	return &proto.SetSecretResponse{}, nil
}

func (f *fakeHostService) DeleteSecret(ctx context.Context, in *proto.DeleteSecretRequest, _ ...grpc.CallOption) (*proto.DeleteSecretResponse, error) {
	f.mu.Lock()
	fn := f.deleteSecretFunc
	f.mu.Unlock()
	if fn != nil {
		if err := fn(ctx, in.Name); err != nil {
			return nil, err
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.secrets, in.Name)
	return &proto.DeleteSecretResponse{}, nil
}

func (f *fakeHostService) ListSecrets(_ context.Context, in *proto.ListSecretsRequest, _ ...grpc.CallOption) (*proto.ListSecretsResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	prefix := strings.TrimSuffix(in.Pattern, "*")
	var names []string
	for k := range f.secrets {
		if strings.HasPrefix(k, prefix) {
			names = append(names, k)
		}
	}
	return &proto.ListSecretsResponse{Names: names}, nil
}

func (f *fakeHostService) GetAuthIdentity(_ context.Context, _ *proto.GetAuthIdentityRequest, _ ...grpc.CallOption) (*proto.GetAuthIdentityResponse, error) {
	return &proto.GetAuthIdentityResponse{}, nil
}

func (f *fakeHostService) ListAuthHandlers(_ context.Context, _ *proto.ListAuthHandlersRequest, _ ...grpc.CallOption) (*proto.ListAuthHandlersResponse, error) {
	return &proto.ListAuthHandlersResponse{}, nil
}

func (f *fakeHostService) GetAuthToken(_ context.Context, _ *proto.GetAuthTokenRequest, _ ...grpc.CallOption) (*proto.GetAuthTokenResponse, error) {
	return &proto.GetAuthTokenResponse{}, nil
}

func (f *fakeHostService) GetAuthGroups(_ context.Context, _ *proto.GetAuthGroupsRequest, _ ...grpc.CallOption) (*proto.GetAuthGroupsResponse, error) {
	return &proto.GetAuthGroupsResponse{}, nil
}

func (f *fakeHostService) PromptAuthResponse(ctx context.Context, in *proto.PromptAuthResponseRequest, _ ...grpc.CallOption) (*proto.PromptAuthResponseResponse, error) {
	f.mu.Lock()
	fn := f.promptFunc
	f.mu.Unlock()
	if fn == nil {
		return nil, status.Error(codes.Unimplemented, "PromptAuthResponse not implemented")
	}
	v, err := fn(ctx, in)
	if err != nil {
		return nil, err
	}
	return &proto.PromptAuthResponseResponse{Value: v}, nil
}
