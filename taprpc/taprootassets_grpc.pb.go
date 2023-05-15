// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package taprpc

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// TaprootAssetsClient is the client API for TaprootAssets service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type TaprootAssetsClient interface {
	// tapcli: `assets list`
	// ListAssets lists the set of assets owned by the target daemon.
	ListAssets(ctx context.Context, in *ListAssetRequest, opts ...grpc.CallOption) (*ListAssetResponse, error)
	// tapcli: `assets utxos`
	// ListUtxos lists the UTXOs managed by the target daemon, and the assets they
	// hold.
	ListUtxos(ctx context.Context, in *ListUtxosRequest, opts ...grpc.CallOption) (*ListUtxosResponse, error)
	// tapcli: `assets groups`
	// ListGroups lists the asset groups known to the target daemon, and the assets
	// held in each group.
	ListGroups(ctx context.Context, in *ListGroupsRequest, opts ...grpc.CallOption) (*ListGroupsResponse, error)
	// tapcli: `assets balance`
	// ListBalances lists asset balances
	ListBalances(ctx context.Context, in *ListBalancesRequest, opts ...grpc.CallOption) (*ListBalancesResponse, error)
	// tapcli: `assets transfers`
	// ListTransfers lists outbound asset transfers tracked by the target daemon.
	ListTransfers(ctx context.Context, in *ListTransfersRequest, opts ...grpc.CallOption) (*ListTransfersResponse, error)
	// tapcli: `stop`
	// StopDaemon will send a shutdown request to the interrupt handler, triggering
	// a graceful shutdown of the daemon.
	StopDaemon(ctx context.Context, in *StopRequest, opts ...grpc.CallOption) (*StopResponse, error)
	// tapcli: `debuglevel`
	// DebugLevel allows a caller to programmatically set the logging verbosity of
	// tapd. The logging can be targeted according to a coarse daemon-wide logging
	// level, or in a granular fashion to specify the logging for a target
	// sub-system.
	DebugLevel(ctx context.Context, in *DebugLevelRequest, opts ...grpc.CallOption) (*DebugLevelResponse, error)
	// tapcli: `addrs query`
	// QueryAddrs queries the set of Taproot Asset addresses stored in the
	// database.
	QueryAddrs(ctx context.Context, in *QueryAddrRequest, opts ...grpc.CallOption) (*QueryAddrResponse, error)
	// tapcli: `addrs new`
	// NewAddr makes a new address from the set of request params.
	NewAddr(ctx context.Context, in *NewAddrRequest, opts ...grpc.CallOption) (*Addr, error)
	// tapcli: `addrs decode`
	// DecodeAddr decode a Taproot Asset address into a partial asset message that
	// represents the asset it wants to receive.
	DecodeAddr(ctx context.Context, in *DecodeAddrRequest, opts ...grpc.CallOption) (*Addr, error)
	// tapcli: `addrs receives`
	// List all receives for incoming asset transfers for addresses that were
	// created previously.
	AddrReceives(ctx context.Context, in *AddrReceivesRequest, opts ...grpc.CallOption) (*AddrReceivesResponse, error)
	// tapcli: `proofs verify`
	// VerifyProof attempts to verify a given proof file that claims to be anchored
	// at the specified genesis point.
	VerifyProof(ctx context.Context, in *ProofFile, opts ...grpc.CallOption) (*ProofVerifyResponse, error)
	// tapcli: `proofs export`
	// ExportProof exports the latest raw proof file anchored at the specified
	// script_key.
	ExportProof(ctx context.Context, in *ExportProofRequest, opts ...grpc.CallOption) (*ProofFile, error)
	// tapcli: `proofs import`
	// ImportProof attempts to import a proof file into the daemon. If successful,
	// a new asset will be inserted on disk, spendable using the specified target
	// script key, and internal key.
	ImportProof(ctx context.Context, in *ImportProofRequest, opts ...grpc.CallOption) (*ImportProofResponse, error)
	// tapcli: `assets send`
	// SendAsset uses one or multiple passed taro address(es) to attempt to
	// complete an asset send. The method returns information w.r.t the on chain
	// send, as well as the proof file information the receiver needs to fully
	// receive the asset.
	SendAsset(ctx context.Context, in *SendAssetRequest, opts ...grpc.CallOption) (*SendAssetResponse, error)
	// SubscribeSendAssetEventNtfns registers a subscription to the event
	// notification stream which relates to the asset sending process.
	SubscribeSendAssetEventNtfns(ctx context.Context, in *SubscribeSendAssetEventNtfnsRequest, opts ...grpc.CallOption) (TaprootAssets_SubscribeSendAssetEventNtfnsClient, error)
	// FetchAssetMeta allows a caller to fetch the reveal meta data for an asset
	// either by the asset ID for that asset, or a meta hash.
	FetchAssetMeta(ctx context.Context, in *FetchAssetMetaRequest, opts ...grpc.CallOption) (*AssetMeta, error)
}

type taprootAssetsClient struct {
	cc grpc.ClientConnInterface
}

func NewTaprootAssetsClient(cc grpc.ClientConnInterface) TaprootAssetsClient {
	return &taprootAssetsClient{cc}
}

func (c *taprootAssetsClient) ListAssets(ctx context.Context, in *ListAssetRequest, opts ...grpc.CallOption) (*ListAssetResponse, error) {
	out := new(ListAssetResponse)
	err := c.cc.Invoke(ctx, "/taprpc.TaprootAssets/ListAssets", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *taprootAssetsClient) ListUtxos(ctx context.Context, in *ListUtxosRequest, opts ...grpc.CallOption) (*ListUtxosResponse, error) {
	out := new(ListUtxosResponse)
	err := c.cc.Invoke(ctx, "/taprpc.TaprootAssets/ListUtxos", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *taprootAssetsClient) ListGroups(ctx context.Context, in *ListGroupsRequest, opts ...grpc.CallOption) (*ListGroupsResponse, error) {
	out := new(ListGroupsResponse)
	err := c.cc.Invoke(ctx, "/taprpc.TaprootAssets/ListGroups", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *taprootAssetsClient) ListBalances(ctx context.Context, in *ListBalancesRequest, opts ...grpc.CallOption) (*ListBalancesResponse, error) {
	out := new(ListBalancesResponse)
	err := c.cc.Invoke(ctx, "/taprpc.TaprootAssets/ListBalances", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *taprootAssetsClient) ListTransfers(ctx context.Context, in *ListTransfersRequest, opts ...grpc.CallOption) (*ListTransfersResponse, error) {
	out := new(ListTransfersResponse)
	err := c.cc.Invoke(ctx, "/taprpc.TaprootAssets/ListTransfers", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *taprootAssetsClient) StopDaemon(ctx context.Context, in *StopRequest, opts ...grpc.CallOption) (*StopResponse, error) {
	out := new(StopResponse)
	err := c.cc.Invoke(ctx, "/taprpc.TaprootAssets/StopDaemon", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *taprootAssetsClient) DebugLevel(ctx context.Context, in *DebugLevelRequest, opts ...grpc.CallOption) (*DebugLevelResponse, error) {
	out := new(DebugLevelResponse)
	err := c.cc.Invoke(ctx, "/taprpc.TaprootAssets/DebugLevel", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *taprootAssetsClient) QueryAddrs(ctx context.Context, in *QueryAddrRequest, opts ...grpc.CallOption) (*QueryAddrResponse, error) {
	out := new(QueryAddrResponse)
	err := c.cc.Invoke(ctx, "/taprpc.TaprootAssets/QueryAddrs", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *taprootAssetsClient) NewAddr(ctx context.Context, in *NewAddrRequest, opts ...grpc.CallOption) (*Addr, error) {
	out := new(Addr)
	err := c.cc.Invoke(ctx, "/taprpc.TaprootAssets/NewAddr", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *taprootAssetsClient) DecodeAddr(ctx context.Context, in *DecodeAddrRequest, opts ...grpc.CallOption) (*Addr, error) {
	out := new(Addr)
	err := c.cc.Invoke(ctx, "/taprpc.TaprootAssets/DecodeAddr", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *taprootAssetsClient) AddrReceives(ctx context.Context, in *AddrReceivesRequest, opts ...grpc.CallOption) (*AddrReceivesResponse, error) {
	out := new(AddrReceivesResponse)
	err := c.cc.Invoke(ctx, "/taprpc.TaprootAssets/AddrReceives", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *taprootAssetsClient) VerifyProof(ctx context.Context, in *ProofFile, opts ...grpc.CallOption) (*ProofVerifyResponse, error) {
	out := new(ProofVerifyResponse)
	err := c.cc.Invoke(ctx, "/taprpc.TaprootAssets/VerifyProof", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *taprootAssetsClient) ExportProof(ctx context.Context, in *ExportProofRequest, opts ...grpc.CallOption) (*ProofFile, error) {
	out := new(ProofFile)
	err := c.cc.Invoke(ctx, "/taprpc.TaprootAssets/ExportProof", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *taprootAssetsClient) ImportProof(ctx context.Context, in *ImportProofRequest, opts ...grpc.CallOption) (*ImportProofResponse, error) {
	out := new(ImportProofResponse)
	err := c.cc.Invoke(ctx, "/taprpc.TaprootAssets/ImportProof", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *taprootAssetsClient) SendAsset(ctx context.Context, in *SendAssetRequest, opts ...grpc.CallOption) (*SendAssetResponse, error) {
	out := new(SendAssetResponse)
	err := c.cc.Invoke(ctx, "/taprpc.TaprootAssets/SendAsset", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *taprootAssetsClient) SubscribeSendAssetEventNtfns(ctx context.Context, in *SubscribeSendAssetEventNtfnsRequest, opts ...grpc.CallOption) (TaprootAssets_SubscribeSendAssetEventNtfnsClient, error) {
	stream, err := c.cc.NewStream(ctx, &TaprootAssets_ServiceDesc.Streams[0], "/taprpc.TaprootAssets/SubscribeSendAssetEventNtfns", opts...)
	if err != nil {
		return nil, err
	}
	x := &taprootAssetsSubscribeSendAssetEventNtfnsClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type TaprootAssets_SubscribeSendAssetEventNtfnsClient interface {
	Recv() (*SendAssetEvent, error)
	grpc.ClientStream
}

type taprootAssetsSubscribeSendAssetEventNtfnsClient struct {
	grpc.ClientStream
}

func (x *taprootAssetsSubscribeSendAssetEventNtfnsClient) Recv() (*SendAssetEvent, error) {
	m := new(SendAssetEvent)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *taprootAssetsClient) FetchAssetMeta(ctx context.Context, in *FetchAssetMetaRequest, opts ...grpc.CallOption) (*AssetMeta, error) {
	out := new(AssetMeta)
	err := c.cc.Invoke(ctx, "/taprpc.TaprootAssets/FetchAssetMeta", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// TaprootAssetsServer is the server API for TaprootAssets service.
// All implementations must embed UnimplementedTaprootAssetsServer
// for forward compatibility
type TaprootAssetsServer interface {
	// tapcli: `assets list`
	// ListAssets lists the set of assets owned by the target daemon.
	ListAssets(context.Context, *ListAssetRequest) (*ListAssetResponse, error)
	// tapcli: `assets utxos`
	// ListUtxos lists the UTXOs managed by the target daemon, and the assets they
	// hold.
	ListUtxos(context.Context, *ListUtxosRequest) (*ListUtxosResponse, error)
	// tapcli: `assets groups`
	// ListGroups lists the asset groups known to the target daemon, and the assets
	// held in each group.
	ListGroups(context.Context, *ListGroupsRequest) (*ListGroupsResponse, error)
	// tapcli: `assets balance`
	// ListBalances lists asset balances
	ListBalances(context.Context, *ListBalancesRequest) (*ListBalancesResponse, error)
	// tapcli: `assets transfers`
	// ListTransfers lists outbound asset transfers tracked by the target daemon.
	ListTransfers(context.Context, *ListTransfersRequest) (*ListTransfersResponse, error)
	// tapcli: `stop`
	// StopDaemon will send a shutdown request to the interrupt handler, triggering
	// a graceful shutdown of the daemon.
	StopDaemon(context.Context, *StopRequest) (*StopResponse, error)
	// tapcli: `debuglevel`
	// DebugLevel allows a caller to programmatically set the logging verbosity of
	// tapd. The logging can be targeted according to a coarse daemon-wide logging
	// level, or in a granular fashion to specify the logging for a target
	// sub-system.
	DebugLevel(context.Context, *DebugLevelRequest) (*DebugLevelResponse, error)
	// tapcli: `addrs query`
	// QueryAddrs queries the set of Taproot Asset addresses stored in the
	// database.
	QueryAddrs(context.Context, *QueryAddrRequest) (*QueryAddrResponse, error)
	// tapcli: `addrs new`
	// NewAddr makes a new address from the set of request params.
	NewAddr(context.Context, *NewAddrRequest) (*Addr, error)
	// tapcli: `addrs decode`
	// DecodeAddr decode a Taproot Asset address into a partial asset message that
	// represents the asset it wants to receive.
	DecodeAddr(context.Context, *DecodeAddrRequest) (*Addr, error)
	// tapcli: `addrs receives`
	// List all receives for incoming asset transfers for addresses that were
	// created previously.
	AddrReceives(context.Context, *AddrReceivesRequest) (*AddrReceivesResponse, error)
	// tapcli: `proofs verify`
	// VerifyProof attempts to verify a given proof file that claims to be anchored
	// at the specified genesis point.
	VerifyProof(context.Context, *ProofFile) (*ProofVerifyResponse, error)
	// tapcli: `proofs export`
	// ExportProof exports the latest raw proof file anchored at the specified
	// script_key.
	ExportProof(context.Context, *ExportProofRequest) (*ProofFile, error)
	// tapcli: `proofs import`
	// ImportProof attempts to import a proof file into the daemon. If successful,
	// a new asset will be inserted on disk, spendable using the specified target
	// script key, and internal key.
	ImportProof(context.Context, *ImportProofRequest) (*ImportProofResponse, error)
	// tapcli: `assets send`
	// SendAsset uses one or multiple passed taro address(es) to attempt to
	// complete an asset send. The method returns information w.r.t the on chain
	// send, as well as the proof file information the receiver needs to fully
	// receive the asset.
	SendAsset(context.Context, *SendAssetRequest) (*SendAssetResponse, error)
	// SubscribeSendAssetEventNtfns registers a subscription to the event
	// notification stream which relates to the asset sending process.
	SubscribeSendAssetEventNtfns(*SubscribeSendAssetEventNtfnsRequest, TaprootAssets_SubscribeSendAssetEventNtfnsServer) error
	// FetchAssetMeta allows a caller to fetch the reveal meta data for an asset
	// either by the asset ID for that asset, or a meta hash.
	FetchAssetMeta(context.Context, *FetchAssetMetaRequest) (*AssetMeta, error)
	mustEmbedUnimplementedTaprootAssetsServer()
}

// UnimplementedTaprootAssetsServer must be embedded to have forward compatible implementations.
type UnimplementedTaprootAssetsServer struct {
}

func (UnimplementedTaprootAssetsServer) ListAssets(context.Context, *ListAssetRequest) (*ListAssetResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListAssets not implemented")
}
func (UnimplementedTaprootAssetsServer) ListUtxos(context.Context, *ListUtxosRequest) (*ListUtxosResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListUtxos not implemented")
}
func (UnimplementedTaprootAssetsServer) ListGroups(context.Context, *ListGroupsRequest) (*ListGroupsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListGroups not implemented")
}
func (UnimplementedTaprootAssetsServer) ListBalances(context.Context, *ListBalancesRequest) (*ListBalancesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListBalances not implemented")
}
func (UnimplementedTaprootAssetsServer) ListTransfers(context.Context, *ListTransfersRequest) (*ListTransfersResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListTransfers not implemented")
}
func (UnimplementedTaprootAssetsServer) StopDaemon(context.Context, *StopRequest) (*StopResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method StopDaemon not implemented")
}
func (UnimplementedTaprootAssetsServer) DebugLevel(context.Context, *DebugLevelRequest) (*DebugLevelResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DebugLevel not implemented")
}
func (UnimplementedTaprootAssetsServer) QueryAddrs(context.Context, *QueryAddrRequest) (*QueryAddrResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method QueryAddrs not implemented")
}
func (UnimplementedTaprootAssetsServer) NewAddr(context.Context, *NewAddrRequest) (*Addr, error) {
	return nil, status.Errorf(codes.Unimplemented, "method NewAddr not implemented")
}
func (UnimplementedTaprootAssetsServer) DecodeAddr(context.Context, *DecodeAddrRequest) (*Addr, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DecodeAddr not implemented")
}
func (UnimplementedTaprootAssetsServer) AddrReceives(context.Context, *AddrReceivesRequest) (*AddrReceivesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AddrReceives not implemented")
}
func (UnimplementedTaprootAssetsServer) VerifyProof(context.Context, *ProofFile) (*ProofVerifyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method VerifyProof not implemented")
}
func (UnimplementedTaprootAssetsServer) ExportProof(context.Context, *ExportProofRequest) (*ProofFile, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ExportProof not implemented")
}
func (UnimplementedTaprootAssetsServer) ImportProof(context.Context, *ImportProofRequest) (*ImportProofResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ImportProof not implemented")
}
func (UnimplementedTaprootAssetsServer) SendAsset(context.Context, *SendAssetRequest) (*SendAssetResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SendAsset not implemented")
}
func (UnimplementedTaprootAssetsServer) SubscribeSendAssetEventNtfns(*SubscribeSendAssetEventNtfnsRequest, TaprootAssets_SubscribeSendAssetEventNtfnsServer) error {
	return status.Errorf(codes.Unimplemented, "method SubscribeSendAssetEventNtfns not implemented")
}
func (UnimplementedTaprootAssetsServer) FetchAssetMeta(context.Context, *FetchAssetMetaRequest) (*AssetMeta, error) {
	return nil, status.Errorf(codes.Unimplemented, "method FetchAssetMeta not implemented")
}
func (UnimplementedTaprootAssetsServer) mustEmbedUnimplementedTaprootAssetsServer() {}

// UnsafeTaprootAssetsServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to TaprootAssetsServer will
// result in compilation errors.
type UnsafeTaprootAssetsServer interface {
	mustEmbedUnimplementedTaprootAssetsServer()
}

func RegisterTaprootAssetsServer(s grpc.ServiceRegistrar, srv TaprootAssetsServer) {
	s.RegisterService(&TaprootAssets_ServiceDesc, srv)
}

func _TaprootAssets_ListAssets_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListAssetRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TaprootAssetsServer).ListAssets(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/taprpc.TaprootAssets/ListAssets",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TaprootAssetsServer).ListAssets(ctx, req.(*ListAssetRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TaprootAssets_ListUtxos_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListUtxosRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TaprootAssetsServer).ListUtxos(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/taprpc.TaprootAssets/ListUtxos",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TaprootAssetsServer).ListUtxos(ctx, req.(*ListUtxosRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TaprootAssets_ListGroups_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListGroupsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TaprootAssetsServer).ListGroups(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/taprpc.TaprootAssets/ListGroups",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TaprootAssetsServer).ListGroups(ctx, req.(*ListGroupsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TaprootAssets_ListBalances_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListBalancesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TaprootAssetsServer).ListBalances(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/taprpc.TaprootAssets/ListBalances",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TaprootAssetsServer).ListBalances(ctx, req.(*ListBalancesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TaprootAssets_ListTransfers_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListTransfersRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TaprootAssetsServer).ListTransfers(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/taprpc.TaprootAssets/ListTransfers",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TaprootAssetsServer).ListTransfers(ctx, req.(*ListTransfersRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TaprootAssets_StopDaemon_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(StopRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TaprootAssetsServer).StopDaemon(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/taprpc.TaprootAssets/StopDaemon",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TaprootAssetsServer).StopDaemon(ctx, req.(*StopRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TaprootAssets_DebugLevel_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DebugLevelRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TaprootAssetsServer).DebugLevel(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/taprpc.TaprootAssets/DebugLevel",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TaprootAssetsServer).DebugLevel(ctx, req.(*DebugLevelRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TaprootAssets_QueryAddrs_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(QueryAddrRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TaprootAssetsServer).QueryAddrs(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/taprpc.TaprootAssets/QueryAddrs",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TaprootAssetsServer).QueryAddrs(ctx, req.(*QueryAddrRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TaprootAssets_NewAddr_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(NewAddrRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TaprootAssetsServer).NewAddr(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/taprpc.TaprootAssets/NewAddr",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TaprootAssetsServer).NewAddr(ctx, req.(*NewAddrRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TaprootAssets_DecodeAddr_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DecodeAddrRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TaprootAssetsServer).DecodeAddr(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/taprpc.TaprootAssets/DecodeAddr",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TaprootAssetsServer).DecodeAddr(ctx, req.(*DecodeAddrRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TaprootAssets_AddrReceives_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AddrReceivesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TaprootAssetsServer).AddrReceives(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/taprpc.TaprootAssets/AddrReceives",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TaprootAssetsServer).AddrReceives(ctx, req.(*AddrReceivesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TaprootAssets_VerifyProof_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ProofFile)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TaprootAssetsServer).VerifyProof(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/taprpc.TaprootAssets/VerifyProof",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TaprootAssetsServer).VerifyProof(ctx, req.(*ProofFile))
	}
	return interceptor(ctx, in, info, handler)
}

func _TaprootAssets_ExportProof_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ExportProofRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TaprootAssetsServer).ExportProof(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/taprpc.TaprootAssets/ExportProof",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TaprootAssetsServer).ExportProof(ctx, req.(*ExportProofRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TaprootAssets_ImportProof_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ImportProofRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TaprootAssetsServer).ImportProof(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/taprpc.TaprootAssets/ImportProof",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TaprootAssetsServer).ImportProof(ctx, req.(*ImportProofRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TaprootAssets_SendAsset_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SendAssetRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TaprootAssetsServer).SendAsset(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/taprpc.TaprootAssets/SendAsset",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TaprootAssetsServer).SendAsset(ctx, req.(*SendAssetRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TaprootAssets_SubscribeSendAssetEventNtfns_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(SubscribeSendAssetEventNtfnsRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(TaprootAssetsServer).SubscribeSendAssetEventNtfns(m, &taprootAssetsSubscribeSendAssetEventNtfnsServer{stream})
}

type TaprootAssets_SubscribeSendAssetEventNtfnsServer interface {
	Send(*SendAssetEvent) error
	grpc.ServerStream
}

type taprootAssetsSubscribeSendAssetEventNtfnsServer struct {
	grpc.ServerStream
}

func (x *taprootAssetsSubscribeSendAssetEventNtfnsServer) Send(m *SendAssetEvent) error {
	return x.ServerStream.SendMsg(m)
}

func _TaprootAssets_FetchAssetMeta_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(FetchAssetMetaRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TaprootAssetsServer).FetchAssetMeta(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/taprpc.TaprootAssets/FetchAssetMeta",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TaprootAssetsServer).FetchAssetMeta(ctx, req.(*FetchAssetMetaRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// TaprootAssets_ServiceDesc is the grpc.ServiceDesc for TaprootAssets service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var TaprootAssets_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "taprpc.TaprootAssets",
	HandlerType: (*TaprootAssetsServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "ListAssets",
			Handler:    _TaprootAssets_ListAssets_Handler,
		},
		{
			MethodName: "ListUtxos",
			Handler:    _TaprootAssets_ListUtxos_Handler,
		},
		{
			MethodName: "ListGroups",
			Handler:    _TaprootAssets_ListGroups_Handler,
		},
		{
			MethodName: "ListBalances",
			Handler:    _TaprootAssets_ListBalances_Handler,
		},
		{
			MethodName: "ListTransfers",
			Handler:    _TaprootAssets_ListTransfers_Handler,
		},
		{
			MethodName: "StopDaemon",
			Handler:    _TaprootAssets_StopDaemon_Handler,
		},
		{
			MethodName: "DebugLevel",
			Handler:    _TaprootAssets_DebugLevel_Handler,
		},
		{
			MethodName: "QueryAddrs",
			Handler:    _TaprootAssets_QueryAddrs_Handler,
		},
		{
			MethodName: "NewAddr",
			Handler:    _TaprootAssets_NewAddr_Handler,
		},
		{
			MethodName: "DecodeAddr",
			Handler:    _TaprootAssets_DecodeAddr_Handler,
		},
		{
			MethodName: "AddrReceives",
			Handler:    _TaprootAssets_AddrReceives_Handler,
		},
		{
			MethodName: "VerifyProof",
			Handler:    _TaprootAssets_VerifyProof_Handler,
		},
		{
			MethodName: "ExportProof",
			Handler:    _TaprootAssets_ExportProof_Handler,
		},
		{
			MethodName: "ImportProof",
			Handler:    _TaprootAssets_ImportProof_Handler,
		},
		{
			MethodName: "SendAsset",
			Handler:    _TaprootAssets_SendAsset_Handler,
		},
		{
			MethodName: "FetchAssetMeta",
			Handler:    _TaprootAssets_FetchAssetMeta_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "SubscribeSendAssetEventNtfns",
			Handler:       _TaprootAssets_SubscribeSendAssetEventNtfns_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "taprootassets.proto",
}
