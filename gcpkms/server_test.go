package gcpkms

import (
	"context"
	"fmt"
	"net"
	"testing"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Fake GRPC server for testing purposes.
type fakeServer struct {
	listener net.Listener
	srv      *grpc.Server
}

// Creates a new fake server ready for listening RPC requests.
func newFakeServer(t *testing.T) *fakeServer {
	var f = new(fakeServer)
	var err error

	t.Logf("Creating a new TCP listener")
	f.listener, err = net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("failed to setup listener: %s", err)
	}
	t.Logf("Creating a new GRPC server")
	f.srv = grpc.NewServer()
	kmspb.RegisterKeyManagementServiceServer(f.srv, &fakeService{})
	return f
}

// Serve KMS server. This also registers
// a function to stop listening via t.Cleanup, thus
// you don't have to add it manually.
func (f *fakeServer) Serve(t *testing.T) {
	t.Logf("Serving GRPC on - %s", f.listener.Addr())
	go func() {
		if err := f.srv.Serve(f.listener); err != nil {
			panic(fmt.Errorf("failed to start grpc server: %w", err))
		}
	}()
	t.Cleanup(func() {
		f.Close(t)
	})
}

// Stop the server and listener.
func (f *fakeServer) Close(t *testing.T) {
	t.Logf("Stopping server and listeners: %s", f.listener.Addr().String())
	f.srv.Stop()
}

// Get KeyManagementClient which is suitable for use with fake server.
func (f *fakeServer) Client(t *testing.T) *kms.KeyManagementClient {
	if f.listener == nil {
		t.Fatalf("Client() called before Start")
	}

	ctx := context.Background()
	client, err := kms.NewKeyManagementClient(
		ctx,
		option.WithEndpoint(f.listener.Addr().String()),
		option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
		option.WithTelemetryDisabled(),
		option.WithoutAuthentication(),
	)
	if err != nil {
		t.Fatalf("cannot get KeyManagementClient: %s", err)
	}
	return client
}
