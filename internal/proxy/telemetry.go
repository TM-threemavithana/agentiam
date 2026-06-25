package proxy

import (
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

var Tracer trace.Tracer

func init() {
	Tracer = otel.Tracer("agentiam/proxy")
}

// InitTracer initializes an OpenTelemetry stdout tracer.
func InitTracer() (*sdktrace.TracerProvider, error) {
	exp, err := stdouttrace.New(stdouttrace.WithPrettyPrint())
	if err != nil {
		return nil, err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithSampler(sdktrace.TraceIDRatioBased(0.05)),
	)
	otel.SetTracerProvider(tp)
	Tracer = tp.Tracer("agentiam/proxy")
	return tp, nil
}
