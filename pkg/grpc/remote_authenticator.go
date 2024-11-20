package grpc

import (
	"context"
	"crypto/sha256"
	"sync"
	"time"

	"github.com/buildbarn/bb-storage/pkg/auth"
	"github.com/buildbarn/bb-storage/pkg/clock"
	"github.com/buildbarn/bb-storage/pkg/eviction"
	auth_pb "github.com/buildbarn/bb-storage/pkg/proto/auth"
	"github.com/buildbarn/bb-storage/pkg/util"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

type remoteAuthenticator struct {
	remoteAuthClient auth_pb.AuthenticationClient
	scope            *structpb.Value

	clock            clock.Clock
	maximumCacheSize int

	lock            sync.Mutex
	cachedResponses map[RemoteAuthenticatorCacheKey]*remoteAuthCacheEntry
	evictionSet     eviction.Set[RemoteAuthenticatorCacheKey]
}

// RemoteAuthenticatorCacheKey is the key type for the cache inside
// remoteAuthenticator.
type RemoteAuthenticatorCacheKey [sha256.Size]byte

type remoteAuthCacheEntry struct {
	ready    <-chan struct{}
	response remoteAuthResponse
}

type remoteAuthResponse struct {
	expirationTime time.Time
	authMetadata   *auth.AuthenticationMetadata
	err            error
}

func (ce *remoteAuthCacheEntry) HasExpired(now time.Time) bool {
	select {
	case <-ce.ready:
		return ce.response.expirationTime.Before(now)
	default:
		// Ongoing remote requests have not expired by definition.
		return false
	}
}

// NewRemoteAuthenticator creates a new RemoteAuthenticator for incoming
// requests that forwards headers to a remote service for authentication. The
// result from the remote service is cached.
func NewRemoteAuthenticator(
	client grpc.ClientConnInterface,
	scope *structpb.Value,
	clock clock.Clock,
	evictionSet eviction.Set[RemoteAuthenticatorCacheKey],
	maximumCacheSize int,
) RequestHeadersAuthenticator {
	return &remoteAuthenticator{
		remoteAuthClient: auth_pb.NewAuthenticationClient(client),
		scope:            scope,

		clock:            clock,
		maximumCacheSize: maximumCacheSize,

		cachedResponses: make(map[RemoteAuthenticatorCacheKey]*remoteAuthCacheEntry),
		evictionSet:     evictionSet,
	}
}

func (a *remoteAuthenticator) Authenticate(ctx context.Context, headers map[string][]string) (*auth.AuthenticationMetadata, error) {
	request := &auth_pb.AuthenticateRequest{
		RequestMetadata: make(map[string]*auth_pb.AuthenticateRequest_ValueList, len(headers)),
		Scope:           a.scope,
	}
	for headerKey, headerValues := range headers {
		request.RequestMetadata[headerKey] = &auth_pb.AuthenticateRequest_ValueList{
			Value: headerValues,
		}
	}
	requestBytes, err := proto.Marshal(request)
	if err != nil {
		return nil, util.StatusWrapWithCode(err, codes.Unauthenticated, "Failed to marshal authenticate request")
	}
	// Hash the request to use as a cache key to both save memory and avoid
	// keeping credentials in the memory.
	requestKey := sha256.Sum256(requestBytes)

	a.lock.Lock()
	now := a.clock.Now()
	entry := a.getAndTouchCacheEntry(requestKey)
	if entry != nil && entry.HasExpired(now) {
		entry = nil
	}
	if entry == nil {
		// No valid cache entry available. Deduplicate requests by creating a
		// pending cached response.
		responseReady := make(chan struct{})
		entry = &remoteAuthCacheEntry{
			ready: responseReady,
		}
		a.cachedResponses[requestKey] = entry
		a.lock.Unlock()

		// Perform the remote authentication request.
		entry.response = a.authenticateRemotely(ctx, request)
		close(responseReady)
	} else {
		a.lock.Unlock()

		// Wait for the remote request to finish.
		select {
		case <-ctx.Done():
			return nil, util.StatusWrapWithCode(ctx.Err(), codes.Unauthenticated, "Context cancelled")
		case <-entry.ready:
			// Noop
		}
	}
	return entry.response.authMetadata, entry.response.err
}

func (a *remoteAuthenticator) getAndTouchCacheEntry(requestKey RemoteAuthenticatorCacheKey) *remoteAuthCacheEntry {
	if entry, ok := a.cachedResponses[requestKey]; ok {
		// Cache contains a matching entry.
		a.evictionSet.Touch(requestKey)
		return entry
	}

	// Cache contains no matching entry. Free up space, so that the
	// caller may insert a new entry.
	for len(a.cachedResponses) >= a.maximumCacheSize {
		delete(a.cachedResponses, a.evictionSet.Peek())
		a.evictionSet.Remove()
	}
	a.evictionSet.Insert(requestKey)
	return nil
}

func (a *remoteAuthenticator) authenticateRemotely(ctx context.Context, request *auth_pb.AuthenticateRequest) remoteAuthResponse {
	ret := remoteAuthResponse{
		// The default expirationTime has already passed.
		expirationTime: time.Time{},
	}

	response, err := a.remoteAuthClient.Authenticate(ctx, request)
	if err != nil {
		ret.err = util.StatusWrapWithCode(err, codes.Unauthenticated, "Remote authentication failed")
		return ret
	}

	// An invalid expiration time indicates that the response should not be cached.
	if response.GetCacheExpirationTime().IsValid() {
		// Note that the expiration time might still be valid for non-allow verdicts.
		ret.expirationTime = response.GetCacheExpirationTime().AsTime()
	}

	switch verdict := response.GetVerdict().(type) {
	case *auth_pb.AuthenticateResponse_Allow:
		ret.authMetadata, err = auth.NewAuthenticationMetadataFromProto(verdict.Allow)
		if err != nil {
			ret.err = util.StatusWrapWithCode(err, codes.Unauthenticated, "Bad authentication response")
			return ret
		}
	case *auth_pb.AuthenticateResponse_Deny:
		ret.err = status.Error(codes.Unauthenticated, verdict.Deny)
		return ret
	default:
		ret.err = status.Error(codes.Unauthenticated, "Invalid authentication verdict")
		return ret
	}
	return ret
}
