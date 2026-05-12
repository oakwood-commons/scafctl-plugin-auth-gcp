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
)

// fakeHostService implements proto.HostServiceClient backed by an in-memory map.
type fakeHostService struct {
	mu      sync.Mutex
	secrets map[string]string
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

func (f *fakeHostService) GetSecret(_ context.Context, in *proto.GetSecretRequest, _ ...grpc.CallOption) (*proto.GetSecretResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.secrets[in.Name]
	return &proto.GetSecretResponse{Value: v, Found: ok}, nil
}

func (f *fakeHostService) SetSecret(_ context.Context, in *proto.SetSecretRequest, _ ...grpc.CallOption) (*proto.SetSecretResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.secrets[in.Name] = in.Value
	return &proto.SetSecretResponse{}, nil
}

func (f *fakeHostService) DeleteSecret(_ context.Context, in *proto.DeleteSecretRequest, _ ...grpc.CallOption) (*proto.DeleteSecretResponse, error) {
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
