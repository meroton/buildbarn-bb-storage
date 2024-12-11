// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v5.29.1
// source: pkg/proto/fsac/fsac.proto

package fsac

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	FileSystemAccessCache_GetFileSystemAccessProfile_FullMethodName    = "/buildbarn.fsac.FileSystemAccessCache/GetFileSystemAccessProfile"
	FileSystemAccessCache_UpdateFileSystemAccessProfile_FullMethodName = "/buildbarn.fsac.FileSystemAccessCache/UpdateFileSystemAccessProfile"
)

// FileSystemAccessCacheClient is the client API for FileSystemAccessCache service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type FileSystemAccessCacheClient interface {
	GetFileSystemAccessProfile(ctx context.Context, in *GetFileSystemAccessProfileRequest, opts ...grpc.CallOption) (*FileSystemAccessProfile, error)
	UpdateFileSystemAccessProfile(ctx context.Context, in *UpdateFileSystemAccessProfileRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
}

type fileSystemAccessCacheClient struct {
	cc grpc.ClientConnInterface
}

func NewFileSystemAccessCacheClient(cc grpc.ClientConnInterface) FileSystemAccessCacheClient {
	return &fileSystemAccessCacheClient{cc}
}

func (c *fileSystemAccessCacheClient) GetFileSystemAccessProfile(ctx context.Context, in *GetFileSystemAccessProfileRequest, opts ...grpc.CallOption) (*FileSystemAccessProfile, error) {
	out := new(FileSystemAccessProfile)
	err := c.cc.Invoke(ctx, FileSystemAccessCache_GetFileSystemAccessProfile_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *fileSystemAccessCacheClient) UpdateFileSystemAccessProfile(ctx context.Context, in *UpdateFileSystemAccessProfileRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, FileSystemAccessCache_UpdateFileSystemAccessProfile_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// FileSystemAccessCacheServer is the server API for FileSystemAccessCache service.
// All implementations should embed UnimplementedFileSystemAccessCacheServer
// for forward compatibility
type FileSystemAccessCacheServer interface {
	GetFileSystemAccessProfile(context.Context, *GetFileSystemAccessProfileRequest) (*FileSystemAccessProfile, error)
	UpdateFileSystemAccessProfile(context.Context, *UpdateFileSystemAccessProfileRequest) (*emptypb.Empty, error)
}

// UnimplementedFileSystemAccessCacheServer should be embedded to have forward compatible implementations.
type UnimplementedFileSystemAccessCacheServer struct {
}

func (UnimplementedFileSystemAccessCacheServer) GetFileSystemAccessProfile(context.Context, *GetFileSystemAccessProfileRequest) (*FileSystemAccessProfile, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetFileSystemAccessProfile not implemented")
}
func (UnimplementedFileSystemAccessCacheServer) UpdateFileSystemAccessProfile(context.Context, *UpdateFileSystemAccessProfileRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateFileSystemAccessProfile not implemented")
}

// UnsafeFileSystemAccessCacheServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to FileSystemAccessCacheServer will
// result in compilation errors.
type UnsafeFileSystemAccessCacheServer interface {
	mustEmbedUnimplementedFileSystemAccessCacheServer()
}

func RegisterFileSystemAccessCacheServer(s grpc.ServiceRegistrar, srv FileSystemAccessCacheServer) {
	s.RegisterService(&FileSystemAccessCache_ServiceDesc, srv)
}

func _FileSystemAccessCache_GetFileSystemAccessProfile_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetFileSystemAccessProfileRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FileSystemAccessCacheServer).GetFileSystemAccessProfile(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: FileSystemAccessCache_GetFileSystemAccessProfile_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FileSystemAccessCacheServer).GetFileSystemAccessProfile(ctx, req.(*GetFileSystemAccessProfileRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _FileSystemAccessCache_UpdateFileSystemAccessProfile_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateFileSystemAccessProfileRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FileSystemAccessCacheServer).UpdateFileSystemAccessProfile(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: FileSystemAccessCache_UpdateFileSystemAccessProfile_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FileSystemAccessCacheServer).UpdateFileSystemAccessProfile(ctx, req.(*UpdateFileSystemAccessProfileRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// FileSystemAccessCache_ServiceDesc is the grpc.ServiceDesc for FileSystemAccessCache service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var FileSystemAccessCache_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "buildbarn.fsac.FileSystemAccessCache",
	HandlerType: (*FileSystemAccessCacheServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetFileSystemAccessProfile",
			Handler:    _FileSystemAccessCache_GetFileSystemAccessProfile_Handler,
		},
		{
			MethodName: "UpdateFileSystemAccessProfile",
			Handler:    _FileSystemAccessCache_UpdateFileSystemAccessProfile_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "pkg/proto/fsac/fsac.proto",
}
