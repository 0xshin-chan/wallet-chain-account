package chaindispatcher

import (
	"context"
	"github.com/0xshin-chan/wallet-chain-account/chain"
	"github.com/0xshin-chan/wallet-chain-account/chain/ethereum"
	"github.com/0xshin-chan/wallet-chain-account/chain/solana"
	"github.com/0xshin-chan/wallet-chain-account/config"
	"github.com/0xshin-chan/wallet-chain-account/protobuf/account"
	"github.com/ethereum/go-ethereum/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"runtime/debug"
	"strings"
)

type CommonRequest interface {
	GetChain() string
}

type CommonReply = account.SupportChainsResponse

type ChainType = string

type ChainDispatcher struct {
	registry map[ChainType]chain.IChainAdaptor
}

func NewChainDispatcher(conf *config.Config) (*ChainDispatcher, error) {
	dispatcher := ChainDispatcher{
		registry: make(map[ChainType]chain.IChainAdaptor),
	}

	chainAdaptorFactoryMap := map[string]func(conf *config.Config) (chain.IChainAdaptor, error){
		ethereum.ChainName: ethereum.NewChainAdaptor,
		solana.ChainName:   solana.NewChainAdaptor,
	}

	supportedChains := []string{
		ethereum.ChainName,
		solana.ChainName,
	}

	for _, chainType := range conf.Chains {
		if factory, ok := chainAdaptorFactoryMap[chainType]; ok {
			adaptor, err := factory(conf)
			if err != nil {
				// log.crit用于打印致命错误，并直接结束运行
				log.Crit("Failed to create chain adaptor", "err", err, "chain", chainType)
			}
			dispatcher.registry[chainType] = adaptor
		} else {
			log.Error("Unsupported chain type", "chainType", chainType, "supportedChains", supportedChains)
		}
	}
	return &dispatcher, nil
}

func (d *ChainDispatcher) Interceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	defer func() {
		// 捕获panic
		if e := recover(); e != nil {
			log.Error("panic error", "msg", e)
			// 帮助定位 panic 发生位置（函数调用栈）
			log.Debug(string(debug.Stack()))
			// 生成一个 error，表示 gRPC 的 Internal 状态（内部错误）
			err = status.Errorf(codes.Internal, "Panic err: %v", e)
		}
	}()

	pos := strings.LastIndex(info.FullMethod, "/")
	method := info.FullMethod[pos+1:]
	chainName := req.(CommonRequest).GetChain()
	log.Info(method, "chain", chainName, "req", req)

	resp, err = handler(ctx, req)
	log.Debug("Finish handling", "resp", resp, "err", err)
	return
}

func (d *ChainDispatcher) preHandler(req interface{}) (resp *CommonReply) {
	chainName := req.(CommonRequest).GetChain()
	log.Debug("chain", chainName, "req", req)
	if _, ok := d.registry[chainName]; !ok {
		return &CommonReply{
			Code:    account.ReturnCode_ERROR,
			Msg:     config.UnsupportedOperation,
			Support: false,
		}
	}
	return nil
}

func (d *ChainDispatcher) GetSupportChains(ctx context.Context, request *account.SupportChainsRequest) (*account.SupportChainsResponse, error) {
	resp := d.preHandler(request)
	if resp != nil {
		return &account.SupportChainsResponse{
			Code: account.ReturnCode_ERROR,
			Msg:  config.UnsupportedOperation,
		}, nil
	}
	return d.registry[request.Chain].GetSupportChains(ctx, request)
}

func (d *ChainDispatcher) ConvertAddress(ctx context.Context, request *account.ConvertAddressRequest) (*account.ConvertAddressResponse, error) {
	resp := d.preHandler(request)
	if resp != nil {
		return &account.ConvertAddressResponse{
			Code: account.ReturnCode_ERROR,
			Msg:  "covert address fail at pre handle",
		}, nil
	}
	return d.registry[request.Chain].ConvertAddress(ctx, request)
}

func (d *ChainDispatcher) ValidAddress(ctx context.Context, request *account.ValidAddressRequest) (*account.ValidAddressResponse, error) {
	resp := d.preHandler(request)
	if resp != nil {
		return &account.ValidAddressResponse{
			Code: account.ReturnCode_ERROR,
			Msg:  "valid address error at pre handle",
		}, nil
	}
	return d.registry[request.Chain].ValidAddress(ctx, request)
}

func (d *ChainDispatcher) GetBlockByNumber(ctx context.Context, request *account.BlockNumberRequest) (*account.BlockResponse, error) {
	resp := d.preHandler(request)
	if resp != nil {
		return &account.BlockResponse{
			Code: account.ReturnCode_ERROR,
			Msg:  "get block by number fail at pre handle",
		}, nil
	}
	return d.registry[request.Chain].GetBlockByNumber(ctx, request)
}

func (d *ChainDispatcher) GetBlockByHash(ctx context.Context, request *account.BlockHashRequest) (*account.BlockResponse, error) {
	resp := d.preHandler(request)
	if resp != nil {
		return &account.BlockResponse{
			Code: account.ReturnCode_ERROR,
			Msg:  "get block by hash fail at pre handle",
		}, nil
	}
	return d.registry[request.Chain].GetBlockByHash(ctx, request)
}

func (d *ChainDispatcher) GetBlockHeaderByHash(ctx context.Context, request *account.BlockHeaderHashRequest) (*account.BlockHeaderResponse, error) {
	resp := d.preHandler(request)
	if resp != nil {
		return &account.BlockHeaderResponse{
			Code: account.ReturnCode_ERROR,
			Msg:  "get block header by hash fail at pre handle",
		}, nil
	}
	return d.registry[request.Chain].GetBlockHeaderByHash(ctx, request)
}

func (d *ChainDispatcher) GetBlockHeaderByNumber(ctx context.Context, request *account.BlockHeaderNumberRequest) (*account.BlockHeaderResponse, error) {
	resp := d.preHandler(request)
	if resp != nil {
		return &account.BlockHeaderResponse{
			Code: account.ReturnCode_ERROR,
			Msg:  "get block header by number fail at pre handle",
		}, nil
	}
	return d.registry[request.Chain].GetBlockHeaderByNumber(ctx, request)
}

func (d *ChainDispatcher) GetBlockHeaderByRange(ctx context.Context, request *account.BlockByRangeRequest) (*account.BlockByRangeResponse, error) {
	resp := d.preHandler(request)
	if resp != nil {
		return &account.BlockByRangeResponse{
			Code: account.ReturnCode_ERROR,
			Msg:  "get block range header fail at pre handle",
		}, nil
	}
	return d.registry[request.Chain].GetBlockHeaderByRange(ctx, request)
}

func (d *ChainDispatcher) GetAccount(ctx context.Context, request *account.AccountRequest) (*account.AccountResponse, error) {
	resp := d.preHandler(request)
	if resp != nil {
		return &account.AccountResponse{
			Code: account.ReturnCode_ERROR,
			Msg:  "get account information fail at pre handle",
		}, nil
	}
	return d.registry[request.Chain].GetAccount(ctx, request)
}

func (d *ChainDispatcher) GetFee(ctx context.Context, request *account.FeeRequest) (*account.FeeResponse, error) {
	resp := d.preHandler(request)
	if resp != nil {
		return &account.FeeResponse{
			Code: account.ReturnCode_ERROR,
			Msg:  "get fee fail at pre handle",
		}, nil
	}
	return d.registry[request.Chain].GetFee(ctx, request)
}

func (d *ChainDispatcher) SendTx(ctx context.Context, request *account.SendTxRequest) (*account.SendTxResponse, error) {
	resp := d.preHandler(request)
	if resp != nil {
		return &account.SendTxResponse{
			Code: account.ReturnCode_ERROR,
			Msg:  "send tx fail at pre handle",
		}, nil
	}
	return d.registry[request.Chain].SendTx(ctx, request)
}

func (d *ChainDispatcher) GetTxByAddress(ctx context.Context, request *account.TxAddressRequest) (*account.TxAddressResponse, error) {
	resp := d.preHandler(request)
	if resp != nil {
		return &account.TxAddressResponse{
			Code: account.ReturnCode_ERROR,
			Msg:  "get tx by address fail pre handle",
		}, nil
	}
	return d.registry[request.Chain].GetTxByAddress(ctx, request)
}

func (d *ChainDispatcher) GetTxByHash(ctx context.Context, request *account.TxHashRequest) (*account.TxHashResponse, error) {
	resp := d.preHandler(request)
	if resp != nil {
		return &account.TxHashResponse{
			Code: account.ReturnCode_ERROR,
			Msg:  "get tx by hash fail at pre handle",
		}, nil
	}
	return d.registry[request.Chain].GetTxByHash(ctx, request)
}

func (d *ChainDispatcher) BuildUnSignTransaction(ctx context.Context, request *account.UnSignTransactionRequest) (*account.UnSignTransactionResponse, error) {
	resp := d.preHandler(request)
	if resp != nil {
		return &account.UnSignTransactionResponse{
			Code: account.ReturnCode_ERROR,
			Msg:  "get un sign tx fail at pre handle",
		}, nil
	}
	return d.registry[request.Chain].BuildUnSignTransaction(ctx, request)
}

func (d *ChainDispatcher) BuildSignedTransaction(ctx context.Context, request *account.SignedTransactionRequest) (*account.SignedTransactionResponse, error) {
	resp := d.preHandler(request)
	if resp != nil {
		return &account.SignedTransactionResponse{
			Code: account.ReturnCode_ERROR,
			Msg:  "signed tx fail at pre handle",
		}, nil
	}
	return d.registry[request.Chain].BuildSignedTransaction(ctx, request)
}

func (d *ChainDispatcher) DecodeTransaction(ctx context.Context, request *account.DecodeTransactionRequest) (*account.DecodeTransactionResponse, error) {
	resp := d.preHandler(request)
	if resp != nil {
		return &account.DecodeTransactionResponse{
			Code: account.ReturnCode_ERROR,
			Msg:  "decode tx fail at pre handle",
		}, nil
	}
	return d.registry[request.Chain].DecodeTransaction(ctx, request)
}

func (d *ChainDispatcher) VerifySignedTransaction(ctx context.Context, request *account.VerifyTransactionRequest) (*account.VerifyTransactionResponse, error) {
	resp := d.preHandler(request)
	if resp != nil {
		return &account.VerifyTransactionResponse{
			Code: account.ReturnCode_ERROR,
			Msg:  "verify tx fail at pre handle",
		}, nil
	}
	return d.registry[request.Chain].VerifySignedTransaction(ctx, request)
}

func (d *ChainDispatcher) GetExtraData(ctx context.Context, request *account.ExtraDataRequest) (*account.ExtraDataResponse, error) {
	resp := d.preHandler(request)
	if resp != nil {
		return &account.ExtraDataResponse{
			Code: account.ReturnCode_ERROR,
			Msg:  "get extra data fail at pre handle",
		}, nil
	}
	return d.registry[request.Chain].GetExtraData(ctx, request)
}

func (d *ChainDispatcher) GetNftListByAddress(ctx context.Context, request *account.NftAddressRequest) (*account.NftAddressResponse, error) {
	panic("implement me")
}

func (d *ChainDispatcher) GetNftCollection(ctx context.Context, request *account.NftCollectionRequest) (*account.NftCollectionResponse, error) {
	panic("implement me")
}

func (d *ChainDispatcher) GetNftDetail(ctx context.Context, request *account.NftDetailRequest) (*account.NftDetailResponse, error) {
	panic("implement me")
}

func (d *ChainDispatcher) GetNftHolderList(ctx context.Context, request *account.NftHolderListRequest) (*account.NftHolderListResponse, error) {
	panic("implement me")
}

func (d *ChainDispatcher) GetNftTradeHistory(ctx context.Context, request *account.NftTradeHistoryRequest) (*account.NftTradeHistoryResponse, error) {
	panic("implement me")
}

func (d *ChainDispatcher) GetAddressNftTradeHistory(ctx context.Context, request *account.AddressNftTradeHistoryRequest) (*account.AddressNftTradeHistoryResponse, error) {
	panic("implement me")
}
