package digest

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"strings"

	remoteexecution "github.com/bazelbuild/remote-apis/build/bazel/remote/execution/v2"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	// Keywords that are not permitted to be placed inside instance
	// names by the REv2 protocol. Permitting these would make
	// parsing of URLs, such as the ones provided to the ByteStream
	// service, ambiguous.
	reservedInstanceNameKeywords = map[string]bool{
		"blobs":         true,
		"uploads":       true,
		"actions":       true,
		"actionResults": true,
		"operations":    true,
		"capabilities":  true,
	}
)

// InstanceName is a simple container around REv2 instance name strings.
// Because instance names are embedded in URLs, the REv2 protocol places
// some restrictions on which instance names are valid. This type can
// only be instantiated for values that are valid.
type InstanceName struct {
	value string
}

// EmptyInstanceName corresponds to the instance name "". It is mainly
// declared to be used in places where the instance name doesn't matter
// (e.g., return values of functions in error cases).
var EmptyInstanceName InstanceName

func validateInstanceNameComponents(components []string) error {
	for _, component := range components {
		if component == "" {
			panic("Attempted to create an instance name with an empty component")
		}
		if _, ok := reservedInstanceNameKeywords[component]; ok {
			return status.Errorf(codes.InvalidArgument, "Instance name contains reserved keyword %#v", component)
		}
	}
	return nil
}

// NewInstanceName creates a new InstanceName object that can be used to
// parse digests.
func NewInstanceName(value string) (InstanceName, error) {
	if strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || strings.Contains(value, "//") {
		return InstanceName{}, status.Error(codes.InvalidArgument, "Instance name contains redundant slashes")
	}
	components := strings.FieldsFunc(value, func(r rune) bool { return r == '/' })
	if err := validateInstanceNameComponents(components); err != nil {
		return InstanceName{}, err
	}
	return InstanceName{
		value: value,
	}, nil
}

func newInstanceNameFromComponents(components []string) (InstanceName, error) {
	if err := validateInstanceNameComponents(components); err != nil {
		return InstanceName{}, err
	}
	return InstanceName{
		value: strings.Join(components, "/"),
	}, nil
}

// MustNewInstanceName is identical to NewInstanceName, except that it
// panics in case the instance name is invalid. This function can be
// used as part of unit tests.
func MustNewInstanceName(value string) InstanceName {
	instanceName, err := NewInstanceName(value)
	if err != nil {
		panic(err)
	}
	return instanceName
}

// NewDigest constructs a Digest object from an instance name, hash and
// object size. The object returned by this function is guaranteed to be
// non-degenerate.
func (in InstanceName) NewDigest(hash string, sizeBytes int64) (Digest, error) {
	// Validate the hash.
	if l := len(hash); l != md5.Size*2 && l != sha1.Size*2 &&
		l != sha256.Size*2 && l != sha512.Size384*2 && l != sha512.Size*2 {
		return BadDigest, status.Errorf(codes.InvalidArgument, "Unknown digest hash length: %d characters", l)
	}
	for _, c := range hash {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return BadDigest, status.Errorf(codes.InvalidArgument, "Non-hexadecimal character in digest hash: %#U", c)
		}
	}

	// Validate the size.
	if sizeBytes < 0 {
		return BadDigest, status.Errorf(codes.InvalidArgument, "Invalid digest size: %d bytes", sizeBytes)
	}

	return in.newDigestUnchecked(hash, sizeBytes), nil
}

// NewDigestFromProto constructs a Digest object from an instance name
// and a protocol-level digest object. The object returned by this
// function is guaranteed to be non-degenerate.
func (in InstanceName) NewDigestFromProto(digest *remoteexecution.Digest) (Digest, error) {
	if digest == nil {
		return BadDigest, status.Error(codes.InvalidArgument, "No digest provided")
	}
	return in.NewDigest(digest.Hash, digest.SizeBytes)
}

// newDigestUnchecked constructs a Digest object from an instance name,
// hash and object size without validating its contents.
func (in InstanceName) newDigestUnchecked(hash string, sizeBytes int64) Digest {
	return Digest{
		value: fmt.Sprintf("%s-%d-%s", hash, sizeBytes, in.value),
	}
}

func (in InstanceName) String() string {
	return in.value
}