package proxy

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	ActiveConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "agentiam_active_connections",
			Help: "Number of active downstream connections to the proxy.",
		},
	)

	QueriesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "agentiam_queries_total",
			Help: "Total number of queries processed.",
		},
		[]string{"status"}, // status=allowed|blocked
	)

	AuthFailuresTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "agentiam_auth_failures_total",
			Help: "Total number of failed authentication attempts.",
		},
	)

	BlockedQueriesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "agentiam_blocked_queries_total",
			Help: "Total number of queries blocked by policy enforcement.",
		},
		[]string{"reason"}, // e.g., forbidden_statement, limit_violation
	)
)

func init() {
	prometheus.MustRegister(ActiveConnections)
	prometheus.MustRegister(QueriesTotal)
	prometheus.MustRegister(AuthFailuresTotal)
	prometheus.MustRegister(BlockedQueriesTotal)
}
