package rpc

import (
	"context"
	"fmt"
	"github.com/0xshin-chan/wallet-chain-account/chaindispatcher"
	"github.com/0xshin-chan/wallet-chain-account/config"
	"github.com/0xshin-chan/wallet-chain-account/protobuf/account"
	"github.com/ethereum/go-ethereum/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"net"
	"sync/atomic"
)

const MaxReceivedMessageSize = 1024 * 1024 * 30000

type RpcService struct {
	conf *config.Config
	account.UnimplementedWalletAccountServiceServer
	// 使用 sync/atomic 里的 atomic.Bool 来记录服务是否已经停止，保证并发安全（多线程读写不会出错）
	stopped atomic.Bool
}

func (s *RpcService) Stop(ctx context.Context) error {
	// 原子操作，把 stopped 状态设为 true，这样别的 goroutine 查询 s.stopped.Load() 时就能知道服务已停
	s.stopped.Store(true)
	return nil
}

func (s *RpcService) Stopped() bool {
	// 原子读取当前值, 判断服务是不是已经停了
	return s.stopped.Load()
}

func NewRpcService(conf *config.Config) (*RpcService, error) {
	rpcService := &RpcService{
		conf: conf,
	}
	return rpcService, nil
}

func (s *RpcService) Start(ctx context.Context) error {
	go func(s *RpcService) {
		addr := fmt.Sprintf("%s:%s", s.conf.RpcServer.Host, s.conf.RpcServer.Port)
		log.Info("rpc server config", "addr", addr)
		opt := grpc.MaxRecvMsgSize(MaxReceivedMessageSize)
		dispatcher, err := chaindispatcher.NewChainDispatcher(s.conf)
		if err != nil {
			log.Error("New eth client fail", "err", err)
			return
		}

		gs := grpc.NewServer(opt, grpc.ChainUnaryInterceptor(dispatcher.Interceptor))
		account.RegisterWalletAccountServiceServer(gs, dispatcher)
		defer gs.GracefulStop()

		listener, err := net.Listen("tcp", addr)
		if err != nil {
			log.Error("Could not start tcp listener")
			return
		}
		reflection.Register(gs)

		log.Info("Grpc info", "port", s.conf.RpcServer.Port, "addr", listener.Addr())
		if err := gs.Serve(listener); err != nil {
			log.Error("grpc server fail", "err", err)
		}
	}(s)
	return nil
}
