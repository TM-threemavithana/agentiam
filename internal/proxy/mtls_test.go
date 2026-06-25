package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"agentiam/internal/policy"

	"github.com/jackc/pgproto3/v2"
)

func generateTestCA() (tls.Certificate, *x509.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	privBytes, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	tlsCert, _ := tls.X509KeyPair(certPEM, keyPEM)
	return tlsCert, cert, nil
}

func generateTestClientCert(caCert *x509.Certificate, caKey interface{}, commonName string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Test Client"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	privBytes, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	return tls.X509KeyPair(certPEM, keyPEM)
}

func TestMutualTLSAuthentication(t *testing.T) {

	// 1. Setup mock policy
	yamlContent := `agents:
  - name: mtls-agent
    key: "$2a$10$w3O1nZ5M2.uC8kC6aDXZM.V9r/6Z2m4V6n/zZ2m4V6n/zZ2m4V6n"
    allowed_statements:
      - "SELECT"
`
	tmpFile, _ := os.CreateTemp("", "policies-*.yaml")
	tmpFile.Write([]byte(yamlContent))
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())
	store, _ := policy.NewStore(nil, tmpFile.Name(), "", slog.New(slog.NewTextHandler(io.Discard, nil)))

	// 2. Setup Certificates
	serverCert, err := GenerateEphemeralCert()
	if err != nil {
		t.Fatalf("failed to gen server cert: %v", err)
	}

	caTlsCert, caX509, err := generateTestCA()
	if err != nil {
		t.Fatalf("failed to gen CA: %v", err)
	}

	clientCert, err := generateTestClientCert(caX509, caTlsCert.PrivateKey, "mtls-agent")
	if err != nil {
		t.Fatalf("failed to gen client cert: %v", err)
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(caX509)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
	}

	// 3. Start proxy listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	port := fmt.Sprintf("%d", l.Addr().(*net.TCPAddr).Port)

	logger := NewLogger(os.Stdout)
	handlers := make(map[ProtocolType]ProtocolHandler)
	server := NewServer("127.0.0.1:"+port, "postgres://dummy:5432", store, tlsConfig, logger, nil, handlers)
	pgHandler := NewPostgresProtocolHandler("postgres://dummy:5432", store, tlsConfig, logger, server)
	server.SetHandler(ProtocolPostgres, pgHandler)

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				session := NewSession(c, "postgres://dummy:5432", store, tlsConfig, logger, server)
				defer session.Close()
				session.Run()
			}(conn)
		}
	}()
	defer l.Close()

	// 4. Test mTLS successful connection
	t.Run("Valid_Client_Cert_Bypasses_Password", func(t *testing.T) {
		conn, err := net.Dial("tcp", "127.0.0.1:"+port)
		if err != nil {
			t.Fatalf("failed to dial: %v", err)
		}
		defer conn.Close()

		// Request TLS
		conn.Write([]byte{0, 0, 0, 8, 4, 210, 22, 47})
		resp := make([]byte, 1)
		conn.Read(resp)
		if resp[0] != 'S' {
			t.Fatalf("expected S, got %c", resp[0])
		}

		tlsClientConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{clientCert},
		})
		if err := tlsClientConn.Handshake(); err != nil {
			t.Fatalf("TLS handshake failed: %v", err)
		}

		frontend := pgproto3.NewFrontend(pgproto3.NewChunkReader(tlsClientConn), tlsClientConn)

		err = frontend.Send(&pgproto3.StartupMessage{
			ProtocolVersion: pgproto3.ProtocolVersionNumber,
			Parameters: map[string]string{
				"user":     "mtls-agent",
				"database": "postgres",
			},
		})
		if err != nil {
			t.Fatalf("failed to send startup: %v", err)
		}

		// Wait for Auth response
		msg, err := frontend.Receive()
		if err != nil {
			t.Fatalf("failed to receive auth response: %v", err)
		}

		switch m := msg.(type) {
		case *pgproto3.AuthenticationOk:
			// Success! Bypassed password and SASL
		case *pgproto3.AuthenticationCleartextPassword:
			t.Fatalf("Expected AuthenticationOk, got CleartextPassword prompt! mTLS failed to bypass.")
		case *pgproto3.ErrorResponse:
			t.Fatalf("Expected AuthenticationOk, got Error: %s", m.Message)
		default:
			t.Fatalf("Unexpected message: %T", m)
		}
	})
}
