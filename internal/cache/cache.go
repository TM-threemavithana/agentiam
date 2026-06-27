package cache

import (
	lru "github.com/hashicorp/golang-lru/v2"
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


