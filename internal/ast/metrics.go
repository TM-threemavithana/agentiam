package ast

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	AstCacheHitsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "agentiam_ast_cache_hits_total",
			Help: "Total number of AST cache hits.",
		},
	)

	AstCacheMissesTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "agentiam_ast_cache_misses_total",
			Help: "Total number of AST cache misses.",
		},
	)

	ParsingDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "agentiam_parsing_duration_seconds",
			Help:    "Histogram of SQL parsing latency.",
			Buckets: prometheus.DefBuckets,
		},
	)
)

func init() {
	prometheus.MustRegister(AstCacheHitsTotal)
	prometheus.MustRegister(AstCacheMissesTotal)
	prometheus.MustRegister(ParsingDuration)
}
