package cache

import (
	"errors"

	lru "github.com/hashicorp/golang-lru"

	"github.com/huahaiwudi/wallet-chain-account/services/http/models"
)

// 缓存能存放的最大数据量是 1,200,000 条
const ListSize = 1200000

type LruCache struct {
	lruStakingRecords *lru.Cache
	lruBridgeRecords  *lru.Cache
}

func NewLruCache() *LruCache {
	// 创建一个新的 LRU 缓存
	lruStakingRecords, err := lru.New(ListSize)
	if err != nil {
		panic(errors.New("Failed to init lruStakingRecords, err :" + err.Error()))
	}
	lruBridgeRecords, err := lru.New(ListSize)
	if err != nil {
		panic(errors.New("Failed to init lruBridgeRecords, err :" + err.Error()))
	}
	return &LruCache{
		lruStakingRecords: lruStakingRecords,
		lruBridgeRecords:  lruBridgeRecords,
	}
}

func (lc *LruCache) GetStakingRecords(key string) (*models.StakingResponse, error) {
	// 从缓存中获取数据
	result, ok := lc.lruStakingRecords.Get(key)
	if !ok {
		return nil, errors.New("Failed to get staking records")
	}
	// 如果有数据，把结果转成 *models.StakingResponse 类型返回
	return result.(*models.StakingResponse), nil
}
