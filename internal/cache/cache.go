package cache

import (
	lru "github.com/hashicorp/golang-lru/v2"
)

type CachedAST struct {
	SQL         string
	LimitParams []int
}

type ASTCache interface {
	Get(key string) (CachedAST, bool)
	Add(key string, val CachedAST)
}

type LocalCache struct {
	lru *lru.Cache[string, CachedAST]
}

func NewLocalCache(size int) (*LocalCache, error) {
	c, err := lru.New[string, CachedAST](size)
	if err != nil {
		return nil, err
	}
	return &LocalCache{lru: c}, nil
}

func (l *LocalCache) Get(key string) (CachedAST, bool) {
	return l.lru.Get(key)
}

func (l *LocalCache) Add(key string, val CachedAST) {
	l.lru.Add(key, val)
}
