package cache

import (
	"context"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/redis/go-redis/v9"
)

type ASTCache interface {
	Get(key string) (string, bool)
	Add(key string, val string)
}

type LocalCache struct {
	lru *lru.Cache[string, string]
}

func NewLocalCache(size int) (*LocalCache, error) {
	c, err := lru.New[string, string](size)
	if err != nil {
		return nil, err
	}
	return &LocalCache{lru: c}, nil
}

func (l *LocalCache) Get(key string) (string, bool) {
	return l.lru.Get(key)
}

func (l *LocalCache) Add(key string, val string) {
	l.lru.Add(key, val)
}

type RedisCache struct {
	client *redis.Client
	ctx    context.Context
	ttl    time.Duration
}

func NewRedisCache(url string, ttl time.Duration) (*RedisCache, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}
	opt.ReadTimeout = 50 * time.Millisecond
	opt.WriteTimeout = 50 * time.Millisecond
	opt.DialTimeout = 100 * time.Millisecond
	client := redis.NewClient(opt)
	
	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
	}
	
	return &RedisCache{
		client: client,
		ctx:    ctx,
		ttl:    ttl,
	}, nil
}

func NewRedisCacheFromClient(client *redis.Client, ttl time.Duration) *RedisCache {
	return &RedisCache{
		client: client,
		ctx:    context.Background(),
		ttl:    ttl,
	}
}

func (r *RedisCache) Get(key string) (string, bool) {
	val, err := r.client.Get(r.ctx, key).Result()
	if err == redis.Nil {
		return "", false
	} else if err != nil {
		return "", false // fallback to miss on error
	}
	return val, true
}

func (r *RedisCache) Add(key string, val string) {
	r.client.Set(r.ctx, key, val, r.ttl)
}

type FallbackCache struct {
	local *LocalCache
	redis *RedisCache
}

func NewFallbackCache(local *LocalCache, r *RedisCache) *FallbackCache {
	return &FallbackCache{local: local, redis: r}
}

func (f *FallbackCache) Get(key string) (string, bool) {
	if val, ok := f.local.Get(key); ok {
		return val, true
	}
	if val, ok := f.redis.Get(key); ok {
		f.local.Add(key, val) // backfill
		return val, true
	}
	return "", false
}

func (f *FallbackCache) Add(key string, val string) {
	f.local.Add(key, val)
	go f.redis.Add(key, val)
}
