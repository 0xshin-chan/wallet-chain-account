package chain

import (
	"context"
	"github.com/huahaiwudi/wallet-chain-account/protobuf/account"
)

type IChainAdaptor interface {
	GetSupportChains(ctx context.Context, req *account.SupportChainsRequest) (*account.SupportChainsResponse, error)
	ConvertAddress(ctx context.Context, req *account.ConvertAddressRequest) (*account.ConvertAddressResponse, error)
	ValidAddress(ctx context.Context, req *account.ValidAddressRequest) (*account.ValidAddressResponse, error)
	GetBlockByNumber(ctx context.Context, req *account.BlockNumberRequest) (*account.BlockResponse, error)
	GetBlockByHash(ctx context.Context, req *account.BlockHashRequest) (*account.BlockResponse, error)
	GetBlockHeaderByHash(ctx context.Context, req *account.BlockHeaderHashRequest) (*account.BlockHeaderResponse, error)
	GetBlockHeaderByNumber(ctx context.Context, req *account.BlockHeaderNumberRequest) (*account.BlockHeaderResponse, error)
	GetBlockHeaderByRange(ctx context.Context, req *account.BlockByRangeRequest) (*account.BlockByRangeResponse, error)
	GetAccount(ctx context.Context, req *account.AccountRequest) (*account.AccountResponse, error)
	GetFee(ctx context.Context, req *account.FeeRequest) (*account.FeeResponse, error)
	SendTx(ctx context.Context, req *account.SendTxRequest) (*account.SendTxResponse, error)
	GetTxByAddress(ctx context.Context, req *account.TxAddressRequest) (*account.TxAddressResponse, error)
	GetTxByHash(ctx context.Context, req *account.TxHashRequest) (*account.TxHashResponse, error)
	BuildUnSignTransaction(ctx context.Context, req *account.UnSignTransactionRequest) (*account.UnSignTransactionResponse, error)
	BuildSignedTransaction(ctx context.Context, req *account.SignedTransactionRequest) (*account.SignedTransactionResponse, error)
	DecodeTransaction(ctx context.Context, req *account.DecodeTransactionRequest) (*account.DecodeTransactionResponse, error)
	VerifySignedTransaction(ctx context.Context, req *account.VerifyTransactionRequest) (*account.VerifyTransactionResponse, error)
	GetExtraData(ctx context.Context, req *account.ExtraDataRequest) (*account.ExtraDataResponse, error)
}
