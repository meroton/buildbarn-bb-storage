package grpc

import (
	"context"

	"github.com/buildbarn/bb-storage/pkg/auth"
)

// RequestHeadersAuthenticator can be used to grant or deny access to a server
// based on request headers, typically from an HTTP or gRPC request.
type RequestHeadersAuthenticator interface {
	Authenticate(ctx context.Context, headers map[string][]string) (*auth.AuthenticationMetadata, error)
}
