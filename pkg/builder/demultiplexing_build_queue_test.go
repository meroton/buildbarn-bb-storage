package builder_test

import (
	"context"
	"testing"

	remoteexecution "github.com/bazelbuild/remote-apis/build/bazel/remote/execution/v2"
	"github.com/buildbarn/bb-storage/internal/mock"
	"github.com/buildbarn/bb-storage/pkg/builder"
	"github.com/buildbarn/bb-storage/pkg/digest"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"google.golang.org/genproto/googleapis/longrunning"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestDemultiplexingBuildQueueGetCapabilities(t *testing.T) {
	ctrl, ctx := gomock.WithContext(context.Background(), t)
	buildQueueGetter := mock.NewMockBuildQueueGetter(ctrl)
	demultiplexingBuildQueue := builder.NewDemultiplexingBuildQueue(buildQueueGetter.Call)

	t.Run("InvalidInstanceName", func(t *testing.T) {
		_, err := demultiplexingBuildQueue.GetCapabilities(ctx, &remoteexecution.GetCapabilitiesRequest{
			InstanceName: "Hello|World",
		})
		require.Equal(t, status.Error(codes.InvalidArgument, "Instance name cannot contain a pipe character"), err)
	})

	t.Run("NonexistentInstanceName", func(t *testing.T) {
		buildQueueGetter.EXPECT().Call("Nonexistent backend").Return(nil, status.Error(codes.NotFound, "Backend not found"))

		_, err := demultiplexingBuildQueue.GetCapabilities(ctx, &remoteexecution.GetCapabilitiesRequest{
			InstanceName: "Nonexistent backend",
		})
		require.Equal(t, status.Error(codes.NotFound, "Failed to obtain backend for instance \"Nonexistent backend\": Backend not found"), err)
	})

	t.Run("BackendFailure", func(t *testing.T) {
		buildQueue := mock.NewMockBuildQueue(ctrl)
		buildQueueGetter.EXPECT().Call("ubuntu1804").Return(buildQueue, nil)
		buildQueue.EXPECT().GetCapabilities(ctx, &remoteexecution.GetCapabilitiesRequest{
			InstanceName: "ubuntu1804",
		}).Return(nil, status.Error(codes.Unavailable, "Server not reachable"))

		_, err := demultiplexingBuildQueue.GetCapabilities(ctx, &remoteexecution.GetCapabilitiesRequest{
			InstanceName: "ubuntu1804",
		})
		require.Equal(t, status.Error(codes.Unavailable, "Server not reachable"), err)
	})

	t.Run("Success", func(t *testing.T) {
		buildQueue := mock.NewMockBuildQueue(ctrl)
		buildQueueGetter.EXPECT().Call("ubuntu1804").Return(buildQueue, nil)
		buildQueue.EXPECT().GetCapabilities(ctx, &remoteexecution.GetCapabilitiesRequest{
			InstanceName: "ubuntu1804",
		}).Return(&remoteexecution.ServerCapabilities{
			CacheCapabilities: &remoteexecution.CacheCapabilities{
				DigestFunction: digest.SupportedDigestFunctions,
			},
		}, nil)

		response, err := demultiplexingBuildQueue.GetCapabilities(ctx, &remoteexecution.GetCapabilitiesRequest{
			InstanceName: "ubuntu1804",
		})
		require.NoError(t, err)
		require.Equal(t, &remoteexecution.ServerCapabilities{
			CacheCapabilities: &remoteexecution.CacheCapabilities{
				DigestFunction: digest.SupportedDigestFunctions,
			},
		}, response)
	})
}

func TestDemultiplexingBuildQueueExecute(t *testing.T) {
	ctrl := gomock.NewController(t)
	buildQueueGetter := mock.NewMockBuildQueueGetter(ctrl)
	demultiplexingBuildQueue := builder.NewDemultiplexingBuildQueue(buildQueueGetter.Call)

	t.Run("InvalidInstanceName", func(t *testing.T) {
		executeServer := mock.NewMockExecution_ExecuteServer(ctrl)

		err := demultiplexingBuildQueue.Execute(&remoteexecution.ExecuteRequest{
			InstanceName: "Hello|World",
			ActionDigest: &remoteexecution.Digest{
				Hash:      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				SizeBytes: 0,
			},
		}, executeServer)
		require.Equal(t, status.Error(codes.InvalidArgument, "Instance name cannot contain a pipe character"), err)
	})

	t.Run("NonexistentInstanceName", func(t *testing.T) {
		buildQueueGetter.EXPECT().Call("Nonexistent backend").Return(nil, status.Error(codes.NotFound, "Backend not found"))
		executeServer := mock.NewMockExecution_ExecuteServer(ctrl)

		err := demultiplexingBuildQueue.Execute(&remoteexecution.ExecuteRequest{
			InstanceName: "Nonexistent backend",
			ActionDigest: &remoteexecution.Digest{
				Hash:      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				SizeBytes: 0,
			},
		}, executeServer)
		require.Equal(t, status.Error(codes.NotFound, "Failed to obtain backend for instance \"Nonexistent backend\": Backend not found"), err)
	})

	t.Run("BackendFailure", func(t *testing.T) {
		buildQueue := mock.NewMockBuildQueue(ctrl)
		buildQueueGetter.EXPECT().Call("ubuntu1804").Return(buildQueue, nil)
		buildQueue.EXPECT().Execute(&remoteexecution.ExecuteRequest{
			InstanceName: "ubuntu1804",
			ActionDigest: &remoteexecution.Digest{
				Hash:      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				SizeBytes: 0,
			},
		}, gomock.Any()).Return(status.Error(codes.Unavailable, "Server not reachable"))
		executeServer := mock.NewMockExecution_ExecuteServer(ctrl)

		err := demultiplexingBuildQueue.Execute(&remoteexecution.ExecuteRequest{
			InstanceName: "ubuntu1804",
			ActionDigest: &remoteexecution.Digest{
				Hash:      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				SizeBytes: 0,
			},
		}, executeServer)
		require.Equal(t, status.Error(codes.Unavailable, "Server not reachable"), err)
	})

	t.Run("Success", func(t *testing.T) {
		buildQueue := mock.NewMockBuildQueue(ctrl)
		buildQueueGetter.EXPECT().Call("ubuntu1804").Return(buildQueue, nil)
		buildQueue.EXPECT().Execute(&remoteexecution.ExecuteRequest{
			InstanceName: "ubuntu1804",
			ActionDigest: &remoteexecution.Digest{
				Hash:      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				SizeBytes: 0,
			},
		}, gomock.Any()).DoAndReturn(
			func(in *remoteexecution.ExecuteRequest, out remoteexecution.Execution_ExecuteServer) error {
				require.NoError(t, out.Send(&longrunning.Operation{
					Name: "fd6ee599-dee5-4390-a221-2bd34cd8ff53",
					Done: true,
				}))
				return nil
			})
		executeServer := mock.NewMockExecution_ExecuteServer(ctrl)
		executeServer.EXPECT().Send(&longrunning.Operation{
			// We should return the operation name prefixed
			// with the instance name, so that
			// WaitExecution() can forward calls to the
			// right backend based on the operation name.
			Name: "ubuntu1804|fd6ee599-dee5-4390-a221-2bd34cd8ff53",
			Done: true,
		})

		err := demultiplexingBuildQueue.Execute(&remoteexecution.ExecuteRequest{
			InstanceName: "ubuntu1804",
			ActionDigest: &remoteexecution.Digest{
				Hash:      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				SizeBytes: 0,
			},
		}, executeServer)
		require.NoError(t, err)
	})
}

func TestDemultiplexingBuildQueueWaitExecution(t *testing.T) {
	ctrl := gomock.NewController(t)
	buildQueueGetter := mock.NewMockBuildQueueGetter(ctrl)
	demultiplexingBuildQueue := builder.NewDemultiplexingBuildQueue(buildQueueGetter.Call)

	t.Run("InvalidInstanceName", func(t *testing.T) {
		waitExecutionServer := mock.NewMockExecution_WaitExecutionServer(ctrl)

		err := demultiplexingBuildQueue.WaitExecution(&remoteexecution.WaitExecutionRequest{
			Name: "This is an operation name that doesn't contain a pipe, meaning we can't demultiplex",
		}, waitExecutionServer)
		require.Equal(t, status.Error(codes.InvalidArgument, "Unable to extract instance from operation name"), err)
	})

	t.Run("NonexistentInstanceName", func(t *testing.T) {
		buildQueueGetter.EXPECT().Call("Nonexistent backend").Return(nil, status.Error(codes.NotFound, "Backend not found"))
		waitExecutionServer := mock.NewMockExecution_WaitExecutionServer(ctrl)

		err := demultiplexingBuildQueue.WaitExecution(&remoteexecution.WaitExecutionRequest{
			Name: "Nonexistent backend|df4ab561-4e81-48c7-a387-edc7d899a76f",
		}, waitExecutionServer)
		require.Equal(t, status.Error(codes.NotFound, "Failed to obtain backend for instance \"Nonexistent backend\": Backend not found"), err)
	})

	t.Run("BackendFailure", func(t *testing.T) {
		buildQueue := mock.NewMockBuildQueue(ctrl)
		buildQueueGetter.EXPECT().Call("ubuntu1804").Return(buildQueue, nil)
		buildQueue.EXPECT().WaitExecution(&remoteexecution.WaitExecutionRequest{
			Name: "df4ab561-4e81-48c7-a387-edc7d899a76f",
		}, gomock.Any()).Return(status.Error(codes.Unavailable, "Server not reachable"))
		waitExecutionServer := mock.NewMockExecution_WaitExecutionServer(ctrl)

		err := demultiplexingBuildQueue.WaitExecution(&remoteexecution.WaitExecutionRequest{
			Name: "ubuntu1804|df4ab561-4e81-48c7-a387-edc7d899a76f",
		}, waitExecutionServer)
		require.Equal(t, status.Error(codes.Unavailable, "Server not reachable"), err)
	})

	t.Run("Success", func(t *testing.T) {
		buildQueue := mock.NewMockBuildQueue(ctrl)
		buildQueueGetter.EXPECT().Call("ubuntu1804").Return(buildQueue, nil)
		buildQueue.EXPECT().WaitExecution(&remoteexecution.WaitExecutionRequest{
			Name: "df4ab561-4e81-48c7-a387-edc7d899a76f",
		}, gomock.Any()).DoAndReturn(
			func(in *remoteexecution.WaitExecutionRequest, out remoteexecution.Execution_WaitExecutionServer) error {
				require.NoError(t, out.Send(&longrunning.Operation{
					Name: "df4ab561-4e81-48c7-a387-edc7d899a76f",
					Done: true,
				}))
				return nil
			})
		waitExecutionServer := mock.NewMockExecution_WaitExecutionServer(ctrl)
		waitExecutionServer.EXPECT().Send(&longrunning.Operation{
			// We should return the operation name prefixed
			// with the instance name, so that the response
			// matches what was provided in the user's
			// WaitExecutionRequest.
			Name: "ubuntu1804|df4ab561-4e81-48c7-a387-edc7d899a76f",
			Done: true,
		})

		err := demultiplexingBuildQueue.WaitExecution(&remoteexecution.WaitExecutionRequest{
			Name: "ubuntu1804|df4ab561-4e81-48c7-a387-edc7d899a76f",
		}, waitExecutionServer)
		require.NoError(t, err)
	})
}
