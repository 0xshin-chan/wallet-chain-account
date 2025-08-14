package solana

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gagliardetto/solana-go/rpc"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cosmos/btcutil/base58"
	"github.com/davecgh/go-spew/spew"
	"github.com/ethereum/go-ethereum/log"
	"github.com/gagliardetto/solana-go"
	associatedtokenaccount "github.com/gagliardetto/solana-go/programs/associated-token-account"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/programs/token"

	account2 "github.com/dapplink-labs/chain-explorer-api/common/account"
	"github.com/huahaiwudi/wallet-chain-account/chain"
	"github.com/huahaiwudi/wallet-chain-account/config"
	"github.com/huahaiwudi/wallet-chain-account/protobuf/account"
)

const ChainName = "Solana"

type ChainAdaptor struct {
	solCli    SolClient
	sdkClient *rpc.Client
	solData   *SolData
}

func NewChainAdaptor(conf *config.Config) (chain.IChainAdaptor, error) {
	rpcUrl := conf.WalletNode.Sol.RpcUrl
	solHttpCli, err := NewSolHttpClient(rpcUrl)
	if err != nil {
		return nil, err
	}
	dataApiUrl := conf.WalletNode.Sol.DataApiUrl
	dataApiKey := conf.WalletNode.Sol.DataApiKey
	dataApiTimeOut := conf.WalletNode.Sol.TimeOut
	solData, err := NewSolScanClient(dataApiUrl, dataApiKey, time.Duration(dataApiTimeOut))
	if err != nil {
		return nil, err
	}
	sdkClient := rpc.New(rpcUrl)
	return &ChainAdaptor{
		solCli:    solHttpCli,
		sdkClient: sdkClient,
		solData:   solData,
	}, nil
}

func (c ChainAdaptor) GetSupportChains(ctx context.Context, req *account.SupportChainsRequest) (*account.SupportChainsResponse, error) {
	return &account.SupportChainsResponse{
		Code:    account.ReturnCode_SUCCESS,
		Msg:     "Support this chain",
		Support: true,
	}, nil
}

func (c ChainAdaptor) ConvertAddress(ctx context.Context, req *account.ConvertAddressRequest) (*account.ConvertAddressResponse, error) {
	resp := &account.ConvertAddressResponse{Code: account.ReturnCode_ERROR}
	pubKeyHex := req.PublicKey
	if ok, msg := validatePublicKey(pubKeyHex); !ok {
		err := fmt.Errorf("invalid public key, err msg = %s", msg)
		resp.Msg = err.Error()
		return resp, err
	}
	accountAddress, err := PubKeyHexToAddress(pubKeyHex)
	if err != nil {
		err := fmt.Errorf("ConvertAddress PubKeyHexToAddress failed: %w", err)
		resp.Msg = err.Error()
		return nil, err
	}
	resp.Code = account.ReturnCode_SUCCESS
	resp.Msg = "convert address success"
	resp.Address = accountAddress
	return resp, nil
}

func (c ChainAdaptor) ValidAddress(ctx context.Context, req *account.ValidAddressRequest) (*account.ValidAddressResponse, error) {
	resp := &account.ValidAddressResponse{Code: account.ReturnCode_ERROR}
	address := req.Address
	if len(address) == 0 {
		err := fmt.Errorf("ValidAddress address is empty")
		resp.Msg = err.Error()
		return resp, err
	}
	if len(address) != 43 && len(address) != 44 {
		err := fmt.Errorf("invalid Solana address length: expected 43 or 44 characters, got %d", len(address))
		resp.Msg = err.Error()
		return resp, err
	}
	resp.Code = account.ReturnCode_SUCCESS
	resp.Valid = true
	return resp, nil

}

func (c ChainAdaptor) GetBlockByNumber(ctx context.Context, req *account.BlockNumberRequest) (*account.BlockResponse, error) {
	resp := &account.BlockResponse{Code: account.ReturnCode_ERROR}
	resultSlot := uint64(req.Height)
	if req.Height == 0 {
		latestSlot, err := c.solCli.GetSlot(Finalized)
		if err != nil {
			err := fmt.Errorf("GetBlockByNumber GetSlot failed: %w", err)
			resp.Msg = err.Error()
			return nil, err
		}
		resultSlot = latestSlot
	}
	blockResult := &BlockResult{}
	if req.ViewTx {
		tempBlockBySlot, err := c.solCli.GetBlockBySlot(resultSlot, Signatures)
		if err != nil {
			err := fmt.Errorf("GetBlockByNumber GetBlockBySlot failed: %w", err)
			resp.Msg = err.Error()
			return nil, err
		}
		blockResult = tempBlockBySlot
	} else {
		tempBlockBySlot, err := c.solCli.GetBlockBySlot(resultSlot, None)
		if err != nil {
			err := fmt.Errorf("GetBlockByNumber GetBlockBySlot failed: %w", err)
			resp.Msg = err.Error()
			return nil, err
		}
		blockResult = tempBlockBySlot
	}
	resp.Hash = blockResult.BlockHash
	resp.Height = int64(resultSlot)
	resp.Code = account.ReturnCode_SUCCESS
	resp.Msg = "GetBlockByNumber success"
	if req.ViewTx {
		resp.Transactions = make([]*account.BlockInfoTransactionList, 0, len(blockResult.Signatures))
		for _, sig := range blockResult.Signatures {
			txInfo := &account.BlockInfoTransactionList{
				Hash: sig,
			}
			resp.Transactions = append(resp.Transactions, txInfo)
		}
	}
	return resp, nil
}

func (c ChainAdaptor) GetBlockByHash(ctx context.Context, req *account.BlockHashRequest) (*account.BlockResponse, error) {
	resp := &account.BlockResponse{
		Code: account.ReturnCode_ERROR,
		Msg:  "not support it now",
	}
	return resp, nil
}

func (c ChainAdaptor) GetBlockHeaderByHash(ctx context.Context, req *account.BlockHeaderHashRequest) (*account.BlockHeaderResponse, error) {
	resp := &account.BlockHeaderResponse{
		Code: account.ReturnCode_ERROR,
		Msg:  "not support it now",
	}
	return resp, nil
}

func (c ChainAdaptor) GetBlockHeaderByNumber(ctx context.Context, req *account.BlockHeaderNumberRequest) (*account.BlockHeaderResponse, error) {
	resp := &account.BlockHeaderResponse{
		Code: account.ReturnCode_ERROR,
	}
	resultSlot := uint64(req.Height)
	if req.Height == 0 {
		latestSlot, err := c.solCli.GetSlot(Finalized)
		if err != nil {
			err := fmt.Errorf("GetBlockHeaderByNumber GetSlot failed: %w", err)
			resp.Msg = err.Error()
			return nil, err
		}
		resultSlot = latestSlot
	}

	blockResult, err := c.solCli.GetBlockBySlot(resultSlot, None)
	if err != nil {
		err := fmt.Errorf("GetBlockHeaderByNumber GetBlockBySlot failed: %w", err)
		resp.Msg = err.Error()
		return nil, err
	}
	blockHead := &account.BlockHeader{
		Hash:       blockResult.BlockHash,
		Number:     strconv.FormatUint(resultSlot, 10),
		ParentHash: blockResult.PreviousBlockhash,
		Time:       uint64(blockResult.BlockTime),
	}
	resp.BlockHeader = blockHead
	resp.Code = account.ReturnCode_SUCCESS
	resp.Msg = "GetBlockHeaderByNumber success"
	return resp, nil
}

func (c ChainAdaptor) GetBlockHeaderByRange(ctx context.Context, req *account.BlockByRangeRequest) (*account.BlockByRangeResponse, error) {
	response := &account.BlockByRangeResponse{Code: account.ReturnCode_ERROR}
	startSlot, _ := strconv.ParseUint(req.Start, 10, 64)
	endSlot, _ := strconv.ParseUint(req.End, 10, 64)

	for slot := startSlot; slot <= endSlot; slot++ {
		blockResult, err := c.solCli.GetBlockBySlot(slot, Signatures)
		if err != nil {
			if len(response.BlockHeader) > 0 {
				response.Code = account.ReturnCode_SUCCESS
				response.Msg = fmt.Sprintf("partial success, stopped at slot %d: %v", slot, err)
				return response, nil
			}
			response.Msg = fmt.Sprintf("failed to get signatures for slot %d: %v", slot, err)
			return response, err
		}

		if len(blockResult.Signatures) == 0 {
			continue
		}

		txResults, err := c.solCli.GetTransactionRange(blockResult.Signatures)
		if err != nil {
			if len(response.BlockHeader) > 0 {
				response.Code = account.ReturnCode_SUCCESS
				response.Msg = fmt.Sprintf("partial success, stopped at slot %d: %v", slot, err)
				return response, nil
			}
			response.Msg = fmt.Sprintf("failed to get transactions for slot %d: %v", slot, err)
			return response, err
		}

		block, err := organizeTransactionsByBlock(txResults)
		if err != nil {
			if len(response.BlockHeader) > 0 {
				response.Code = account.ReturnCode_SUCCESS
				response.Msg = fmt.Sprintf("partial success, stopped at slot %d: %v", slot, err)
				return response, nil
			}
			response.Msg = fmt.Sprintf("failed to organize transactions for slot %d: %v", slot, err)
			return response, err
		}

		if len(block) > 0 {
			response.BlockHeader = append(response.BlockHeader, block...)
		}
	}
	if len(response.BlockHeader) == 0 {
		response.Code = account.ReturnCode_SUCCESS
		response.Msg = "no transactions found in range"
		return response, nil
	}

	response.Code = account.ReturnCode_SUCCESS
	response.Msg = "success"
	return response, nil
}

func (c ChainAdaptor) GetAccount(ctx context.Context, req *account.AccountRequest) (*account.AccountResponse, error) {
	response := &account.AccountResponse{Code: account.ReturnCode_ERROR}
	accountInfoResp, err := c.solCli.GetAccountInfo(req.Address)
	if err != nil {
		err := fmt.Errorf("GetAccount GetAccountInfo failed: %w", err)
		response.Msg = err.Error()
		return nil, err
	}
	latestBlockhashResponse, err := c.solCli.GetLatestBlockhash(Finalized)
	if err != nil {
		err := fmt.Errorf("GetAccount GetLatestBlockhash failed: %w", err)
		response.Msg = err.Error()
		return nil, err
	}
	response.Code = account.ReturnCode_SUCCESS
	response.Msg = "GetAccount success"
	response.Sequence = latestBlockhashResponse
	response.Network = req.Network
	response.Balance = strconv.FormatUint(accountInfoResp.Lamports, 10)
	return response, nil
}

func (c ChainAdaptor) GetFee(ctx context.Context, req *account.FeeRequest) (*account.FeeResponse, error) {
	response := &account.FeeResponse{Code: account.ReturnCode_ERROR}
	baseFee, err := c.solCli.GetFeeForMessage(req.RawTx)
	if err != nil {
		err := fmt.Errorf("GetFee GetFeeForMessage failed: %w", err)
		response.Msg = err.Error()
		return nil, err
	}
	priorityFees, err := c.solCli.GetRecentPrioritizationFees()
	if err != nil {
		err := fmt.Errorf("GetFee GetRecentPrioritizationFees failed: %w", err)
		response.Msg = err.Error()
		return nil, err
	}
	priorityFee := GetSuggestedPriorityFee(priorityFees)
	slowFee := baseFee + uint64(float64(priorityFee)*0.75)
	normalFee := baseFee + priorityFee
	fastFee := baseFee + uint64(float64(priorityFee)*1.25)
	response.SlowFee = strconv.FormatUint(slowFee, 10)
	response.NormalFee = strconv.FormatUint(normalFee, 10)
	response.FastFee = strconv.FormatUint(fastFee, 10)
	return response, nil
}

func (c ChainAdaptor) SendTx(ctx context.Context, req *account.SendTxRequest) (*account.SendTxResponse, error) {
	if req.RawTx == "" {
		return &account.SendTxResponse{
			Code:   account.ReturnCode_ERROR,
			Msg:    "invalid input: empty transaction",
			TxHash: "",
		}, nil
	}
	log.Info("raw tx information:", req.RawTx)
	txHash, err := c.solCli.SendTransaction(req.RawTx, nil)
	if err != nil {
		log.Error("Failed to send transaction", "err", err)
		return &account.SendTxResponse{
			Code:   account.ReturnCode_ERROR,
			Msg:    "failed to send transaction",
			TxHash: "",
		}, err
	}
	return &account.SendTxResponse{
		Code:   account.ReturnCode_SUCCESS,
		Msg:    "transaction sent successfully",
		TxHash: txHash,
	}, nil
}

func (c ChainAdaptor) GetTxByAddress(ctx context.Context, req *account.TxAddressRequest) (*account.TxAddressResponse, error) {
	var err error
	var resp *account2.TransactionResponse[account2.AccountTxResponse]
	fmt.Println("req.ContractAddress", req.ContractAddress)
	if req.ContractAddress != "0x00" && req.ContractAddress != "" {
		log.Info("Spl token transfer record")
		resp, err = c.solData.GetTxByAddress(uint64(req.Page), uint64(req.Pagesize), req.Address, "spl")
	} else {
		log.Info("Sol transfer record")
		resp, err = c.solData.GetTxByAddress(uint64(req.Page), uint64(req.Pagesize), req.Address, "sol")
	}
	if err != nil {
		log.Error("get GetTxByAddress error", "err", err)
		return &account.TxAddressResponse{
			Code: account.ReturnCode_ERROR,
			Msg:  "get tx list fail",
			Tx:   nil,
		}, err
	} else {
		txs := resp.TransactionList
		list := make([]*account.TxMessage, 0, len(txs))
		for i := 0; i < len(txs); i++ {
			list = append(list, &account.TxMessage{
				Hash:   txs[i].TxId,
				To:     txs[i].To,
				From:   txs[i].From,
				Fee:    txs[i].TxId,
				Status: account.TxStatus_Success,
				Value:  txs[i].Amount,
				Type:   1,
				Height: txs[i].Height,
			})
		}
		return &account.TxAddressResponse{
			Code: account.ReturnCode_SUCCESS,
			Msg:  "get tx list success",
			Tx:   list,
		}, nil
	}
}

func (c ChainAdaptor) GetTxByHash(ctx context.Context, req *account.TxHashRequest) (*account.TxHashResponse, error) {
	response := &account.TxHashResponse{
		Code: account.ReturnCode_ERROR,
		Msg:  "",
		Tx:   nil,
	}
	txResult, err := c.solCli.GetTransaction(req.Hash)
	if err != nil {
		response.Msg = err.Error()
		log.Error("GetTransaction failed", "error", err)
		return response, err
	}
	tx, err := buildTxMessage(txResult)
	if err != nil {
		response.Msg = err.Error()
		return response, err
	}
	response.Code = account.ReturnCode_SUCCESS
	response.Msg = "success"
	response.Tx = tx
	return response, nil
}

func (c ChainAdaptor) BuildUnSignTransaction(ctx context.Context, req *account.UnSignTransactionRequest) (*account.UnSignTransactionResponse, error) {
	jsonBytes, err := base64.StdEncoding.DecodeString(req.Base64Tx)
	if err != nil {
		log.Error("Failed to decode base64 string", "err", err)
		return nil, err
	}
	var data TxStructure
	if err := json.Unmarshal(jsonBytes, &data); err != nil {
		log.Error("Failed to parse JSON", "err", err)
		return nil, err
	}
	value, _ := strconv.ParseUint(data.Value, 10, 64)
	fromPubkey, err := solana.PublicKeyFromBase58(data.FromAddress)
	if err != nil {
		return nil, err
	}
	toPubkey, err := solana.PublicKeyFromBase58(data.ToAddress)
	if err != nil {
		return nil, err
	}
	var tx *solana.Transaction
	if isSOLTransfer(data.ContractAddress) {
		tx, err = solana.NewTransaction(
			[]solana.Instruction{
				system.NewTransferInstruction(
					value,
					fromPubkey,
					toPubkey,
				).Build(),
			},
			solana.MustHashFromBase58(data.Nonce),
			solana.TransactionPayer(fromPubkey),
		)
	} else {
		mintPubkey := solana.MustPublicKeyFromBase58(data.ContractAddress)
		fromTokenAccount, _, err := solana.FindAssociatedTokenAddress(
			fromPubkey,
			mintPubkey,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to find associated token address: %w", err)
		}
		toTokenAccount, _, err := solana.FindAssociatedTokenAddress(
			toPubkey,
			mintPubkey,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to find associated token address: %w", err)
		}

		tokenInfo, err := GetTokenSupply(c.sdkClient, mintPubkey)
		if err != nil {
			return nil, fmt.Errorf("failed to get token info: %w", err)
		}
		decimals := tokenInfo.Value.Decimals

		valueFloat, err := strconv.ParseFloat(data.Value, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse value: %w", err)
		}
		actualValue := uint64(valueFloat * math.Pow10(int(decimals)))

		transferInstruction := token.NewTransferInstruction(
			actualValue,
			fromTokenAccount,
			toTokenAccount,
			fromPubkey,
			[]solana.PublicKey{},
		).Build()

		accountInfo, err := GetAccountInfo(c.sdkClient, toTokenAccount)

		if err != nil || accountInfo.Value == nil {
			createATAInstruction := associatedtokenaccount.NewCreateInstruction(
				fromPubkey,
				toPubkey,
				mintPubkey,
			).Build()
			tx, err = solana.NewTransaction(
				[]solana.Instruction{createATAInstruction, transferInstruction},
				solana.MustHashFromBase58(data.Nonce),
				solana.TransactionPayer(fromPubkey),
			)
		} else {
			tx, err = solana.NewTransaction(
				[]solana.Instruction{transferInstruction},
				solana.MustHashFromBase58(data.Nonce),
				solana.TransactionPayer(fromPubkey),
			)
		}
	}
	log.Info("Transaction:", tx.String())
	txm, _ := tx.Message.MarshalBinary()
	signingMessageHex := hex.EncodeToString(txm)
	return &account.UnSignTransactionResponse{
		Code:     account.ReturnCode_SUCCESS,
		Msg:      "Successfully created unsigned transaction",
		UnSignTx: signingMessageHex,
	}, nil
}

func (c ChainAdaptor) BuildSignedTransaction(ctx context.Context, req *account.SignedTransactionRequest) (*account.SignedTransactionResponse, error) {
	jsonBytes, err := base64.StdEncoding.DecodeString(req.Base64Tx)
	if err != nil {
		log.Error("Failed to decode base64 string", "err", err)
		return nil, err
	}

	var data TxStructure
	if err := json.Unmarshal(jsonBytes, &data); err != nil {
		log.Error("Failed to parse JSON", "err", err)
		return nil, err
	}

	value, _ := strconv.ParseUint(data.Value, 10, 64)

	fromPubkey, err := solana.PublicKeyFromBase58(data.FromAddress)
	if err != nil {
		return nil, err
	}

	toPubkey, err := solana.PublicKeyFromBase58(data.ToAddress)
	if err != nil {
		return nil, err
	}

	var tx *solana.Transaction
	if isSOLTransfer(data.ContractAddress) {
		tx, err = solana.NewTransaction(
			[]solana.Instruction{
				system.NewTransferInstruction(
					value,
					fromPubkey,
					toPubkey,
				).Build(),
			},
			solana.MustHashFromBase58(data.Nonce),
			solana.TransactionPayer(fromPubkey),
		)
	} else {
		mintPubkey := solana.MustPublicKeyFromBase58(data.ContractAddress)
		fromTokenAccount, _, err := solana.FindAssociatedTokenAddress(
			fromPubkey,
			mintPubkey,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to find associated token address: %w", err)
		}

		toTokenAccount, _, err := solana.FindAssociatedTokenAddress(
			toPubkey,
			mintPubkey,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to find associated token address: %w", err)
		}

		tokenInfo, err := GetTokenSupply(c.sdkClient, mintPubkey)
		if err != nil {
			return nil, fmt.Errorf("failed to get token info: %w", err)
		}
		decimals := tokenInfo.Value.Decimals

		valueFloat, err := strconv.ParseFloat(data.Value, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse value: %w", err)
		}
		actualValue := uint64(valueFloat * math.Pow10(int(decimals)))

		transferInstruction := token.NewTransferInstruction(
			actualValue,
			fromTokenAccount,
			toTokenAccount,
			fromPubkey,
			[]solana.PublicKey{},
		).Build()
		accountInfo, err := GetAccountInfo(c.sdkClient, toTokenAccount)
		if err != nil || accountInfo.Value == nil {
			createATAInstruction := associatedtokenaccount.NewCreateInstruction(
				fromPubkey,
				toPubkey,
				mintPubkey,
			).Build()
			tx, err = solana.NewTransaction(
				[]solana.Instruction{createATAInstruction, transferInstruction},
				solana.MustHashFromBase58(data.Nonce),
				solana.TransactionPayer(fromPubkey),
			)
		} else {
			tx, err = solana.NewTransaction(
				[]solana.Instruction{transferInstruction},
				solana.MustHashFromBase58(data.Nonce),
				solana.TransactionPayer(fromPubkey),
			)
		}
	}
	if len(tx.Signatures) == 0 {
		tx.Signatures = make([]solana.Signature, 1)
	}

	signatureBytes, err := hex.DecodeString(data.Signature)
	if err != nil {
		log.Error("Failed to decode hex signature", "err", err)
	}

	if len(signatureBytes) != 64 {
		log.Error("Invalid signature length", "length", len(signatureBytes))
	}

	var solanaSig solana.Signature
	copy(solanaSig[:], signatureBytes)

	tx.Signatures[0] = solanaSig

	spew.Dump(tx)
	if err := tx.VerifySignatures(); err != nil {
		log.Info("Invalid signatures", "err", err)
	}

	serializedTx, err := tx.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("Failed to serialize transaction: %w", err)
	}

	log.Info("serialized transaction", "serializedTx", serializedTx)

	base58Tx := base58.Encode(serializedTx)
	return &account.SignedTransactionResponse{
		Code:     account.ReturnCode_SUCCESS,
		Msg:      "Successfully created signed transaction",
		SignedTx: base58Tx,
	}, nil
}

func (c ChainAdaptor) DecodeTransaction(ctx context.Context, req *account.DecodeTransactionRequest) (*account.DecodeTransactionResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (c ChainAdaptor) VerifySignedTransaction(ctx context.Context, req *account.VerifyTransactionRequest) (*account.VerifyTransactionResponse, error) {
	txBytes := base58.Decode(req.Signature)
	tx, err := solana.TransactionFromBytes(txBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize transaction: %w", err)
	}
	if err := tx.VerifySignatures(); err != nil {
		log.Info("Invalid signatures", "err", err)
		return &account.VerifyTransactionResponse{
			Code:   account.ReturnCode_ERROR,
			Msg:    "invalid signature",
			Verify: false,
		}, nil
	}
	return &account.VerifyTransactionResponse{
		Code:   account.ReturnCode_SUCCESS,
		Msg:    "verify signature success",
		Verify: true,
	}, nil
}

func (c ChainAdaptor) GetExtraData(ctx context.Context, req *account.ExtraDataRequest) (*account.ExtraDataResponse, error) {
	//TODO implement me
	panic("implement me")
}

func validatePublicKey(pubKey string) (bool, string) {
	if pubKey == "" {
		return false, "public key cannot be empty"
	}
	pubKeyWithoutPrefix := strings.TrimPrefix(pubKey, "0x")
	if len(pubKeyWithoutPrefix) != 64 {
		return false, "invalid public key length"
	}
	if _, err := hex.DecodeString(pubKeyWithoutPrefix); err != nil {
		return false, "invalid public key format: must be hex string"
	}
	return true, ""
}

func organizeTransactionsByBlock(txResults []*TransactionResult) ([]*account.BlockHeader, error) {
	if len(txResults) == 0 {
		return nil, nil
	}
	blockMap := make(map[uint64]*account.BlockHeader)
	for _, txResult := range txResults {
		if txResult == nil {
			continue
		}
		slot := txResult.Slot

		block, exists := blockMap[slot]
		if !exists {
			block = &account.BlockHeader{
				Number: strconv.FormatUint(slot, 10),
			}

			if txResult.BlockTime != nil {
				block.Time = uint64(*txResult.BlockTime)
			}

			if len(txResult.Transaction.Signatures) > 0 {
				block.Hash = txResult.Transaction.Signatures[0]
			}

			txHashes := make([]string, 0)
			for _, sig := range txResult.Transaction.Signatures {
				txHashes = append(txHashes, sig)
			}
			block.TxHash = strings.Join(txHashes, ",")
			block.GasUsed = txResult.Meta.ComputeUnitsConsumed
			blockMap[slot] = block
		} else {
			if len(txResult.Transaction.Signatures) > 0 {
				if block.TxHash != "" {
					block.TxHash += "," + txResult.Transaction.Signatures[0]
				} else {
					block.TxHash = txResult.Transaction.Signatures[0]
				}
			}
			block.GasUsed += txResult.Meta.ComputeUnitsConsumed
		}
	}

	blocks := make([]*account.BlockHeader, 0, len(blockMap))
	for _, block := range blockMap {
		blocks = append(blocks, block)
	}

	sort.Slice(blocks, func(i, j int) bool {
		heightI, _ := strconv.ParseUint(blocks[i].Number, 10, 64)
		heightJ, _ := strconv.ParseUint(blocks[j].Number, 10, 64)
		return heightI < heightJ
	})

	return blocks, nil
}

func buildTxMessage(txResult *TransactionResult) (*account.TxMessage, error) {
	if txResult == nil {
		return nil, fmt.Errorf("empty transaction result")
	}

	if len(txResult.Transaction.Signatures) == 0 {
		return nil, fmt.Errorf("invalid transaction: no signatures")
	}
	if len(txResult.Transaction.Message.AccountKeys) == 0 {
		return nil, fmt.Errorf("invalid transaction: no account keys")
	}

	tx := &account.TxMessage{
		Hash:   txResult.Transaction.Signatures[0],
		Height: strconv.FormatUint(txResult.Slot, 10),
		Fee:    strconv.FormatUint(txResult.Meta.Fee, 10),
	}

	if txResult.Meta.Err != nil {
		tx.Status = account.TxStatus_Failed
	} else {
		tx.Status = account.TxStatus_Success
	}
	if txResult.BlockTime != nil {
		tx.Datetime = time.Unix(*txResult.BlockTime, 0).Format(time.RFC3339)
	}
	tx.From = txResult.Transaction.Message.AccountKeys[0]
	tx.To = ""
	tx.Value = strconv.Itoa(0)
	if err := processInstructions(txResult, tx); err != nil {
		return nil, fmt.Errorf("failed to process instructions: %w", err)
	}

	return tx, nil
}

func processInstructions(txResult *TransactionResult, tx *account.TxMessage) error {
	for i, inst := range txResult.Transaction.Message.Instructions {
		if inst.ProgramIdIndex >= len(txResult.Transaction.Message.AccountKeys) {
			log.Warn("Invalid program ID index", "instruction", i)
			continue
		}

		if txResult.Transaction.Message.AccountKeys[inst.ProgramIdIndex] != "11111111111111111111111111111111" {
			continue
		}

		if len(inst.Accounts) < 2 {
			log.Warn("Invalid accounts length", "instruction", i)
			continue
		}

		toIndex := inst.Accounts[1]
		if toIndex >= len(txResult.Transaction.Message.AccountKeys) {
			log.Warn("Invalid to account index", "instruction", i)
			continue
		}

		toAddr := txResult.Transaction.Message.AccountKeys[toIndex]
		tx.To = toAddr

		if err := calculateAmount(txResult, toIndex, tx); err != nil {
			log.Warn("Failed to calculate amount", "error", err)
			continue
		}
	}

	return nil
}

func calculateAmount(txResult *TransactionResult, toIndex int, tx *account.TxMessage) error {
	if toIndex >= len(txResult.Meta.PostBalances) || toIndex >= len(txResult.Meta.PreBalances) {
		return fmt.Errorf("invalid balance index: %d", toIndex)
	}

	amount := txResult.Meta.PostBalances[toIndex] - txResult.Meta.PreBalances[toIndex]
	tx.Value = strconv.FormatUint(amount, 10)

	return nil
}

func isSOLTransfer(coinAddress string) bool {
	return coinAddress == "" ||
		coinAddress == "So11111111111111111111111111111111111111112"
}
