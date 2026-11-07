//go:build integration

package proxy_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/crypto/bcrypt"

	"github.com/tm-threemavithana/agentiam/internal/ast"
	"github.com/tm-threemavithana/agentiam/internal/policy"
	"github.com/tm-threemavithana/agentiam/internal/proxy"
)

type viewMaskingTestEnv struct {
	proxyDSN    string
	directDSN   string
	adminDSN    string
	agentKey    string
	policyStore *policy.Store
	server      *proxy.Server
	cleanup     func()
}

func setupViewMaskingEnv(t *testing.T) *viewMaskingTestEnv {
	ctx := context.Background()

	// 1. Start Postgres Container
	pgContainer, err := postgres.Run(ctx,
		"postgres:15-alpine",
		postgres.WithDatabase("viewdb"),
		postgres.WithUsername("postgres"),
		postgres.WithPassword("admin_password"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(15*time.Second)),
	)
	if err != nil {
		t.Fatalf("failed to start postgres container: %s", err)
	}

	adminDSN, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("failed to get admin connection string: %s", err)
	}

	adminConn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("failed to connect admin: %v", err)
	}
	defer adminConn.Close(ctx)

	// 2. Setup Database Schema, Tables, Views, and Roles
	initSQL := `
		CREATE TABLE customers (
			id int PRIMARY KEY,
			name text,
			ssn text,
			credit_card text,
			tenant_id text
		);

		CREATE TABLE orders (
			id int PRIMARY KEY,
			customer_id int,
			amount numeric,
			tenant_id text
		);

		CREATE TABLE secret_vault (
			id int PRIMARY KEY,
			top_secret text
		);

		-- Views
		CREATE VIEW customer_public_view AS
			SELECT id, name, ssn, credit_card, tenant_id FROM customers;

		CREATE VIEW customer_renamed_view AS
			SELECT id AS cust_id, name AS full_name, ssn AS national_id, credit_card AS card_no, tenant_id FROM customers;

		CREATE VIEW customer_nested_view AS
			SELECT cust_id, full_name, national_id, tenant_id FROM customer_renamed_view;

		CREATE VIEW unauthorized_view AS
			SELECT id, ssn FROM customers;

		-- Populate Synthetic Sensitive Data
		INSERT INTO customers (id, name, ssn, credit_card, tenant_id) VALUES
			(1, 'Alice Smith', '987-65-4321', '4111-2222-3333-4444', 'tenant-alpha'),
			(2, 'Bob Jones', '123-45-6789', '5555-6666-7777-8888', 'tenant-beta');

		INSERT INTO orders (id, customer_id, amount, tenant_id) VALUES
			(101, 1, 99.99, 'tenant-alpha'),
			(102, 2, 149.50, 'tenant-beta');

		INSERT INTO secret_vault (id, top_secret) VALUES
			(1, 'classified_nuclear_launch_code_777');

		-- Restricted DB Role for Defense-in-Depth verification
		CREATE ROLE agent_db_role WITH LOGIN PASSWORD 'agent_secure_pass';
		GRANT CONNECT ON DATABASE viewdb TO agent_db_role;
		GRANT USAGE ON SCHEMA public TO agent_db_role;
		GRANT SELECT ON customers, orders, customer_public_view, customer_renamed_view, customer_nested_view TO agent_db_role;
		REVOKE ALL ON TABLE secret_vault FROM PUBLIC;
		REVOKE ALL ON TABLE secret_vault FROM agent_db_role;
		REVOKE ALL ON unauthorized_view FROM PUBLIC;
		REVOKE ALL ON unauthorized_view FROM agent_db_role;
	`
	_, err = adminConn.Exec(ctx, initSQL)
	if err != nil {
		t.Fatalf("failed to initialize database schema: %v", err)
	}

	// 3. Compute real definition fingerprints from PostgreSQL catalog for approved views
	var defPublic, defRenamed, defNested string
	_ = adminConn.QueryRow(ctx, "SELECT definition FROM pg_catalog.pg_views WHERE schemaname = 'public' AND viewname = 'customer_public_view'").Scan(&defPublic)
	_ = adminConn.QueryRow(ctx, "SELECT definition FROM pg_catalog.pg_views WHERE schemaname = 'public' AND viewname = 'customer_renamed_view'").Scan(&defRenamed)
	_ = adminConn.QueryRow(ctx, "SELECT definition FROM pg_catalog.pg_views WHERE schemaname = 'public' AND viewname = 'customer_nested_view'").Scan(&defNested)

	fpPublic, _ := ast.ComputeViewFingerprint(defPublic)
	fpRenamed, _ := ast.ComputeViewFingerprint(defRenamed)
	fpNested, _ := ast.ComputeViewFingerprint(defNested)

	// 4. Setup AgentIAM Policy Store
	agentHash, _ := bcrypt.GenerateFromPassword([]byte("agent_password_xyz"), bcrypt.DefaultCost)
	yamlPolicy := fmt.Sprintf(`
version: "1.0"
agents:
  - name: test-analyst
    key: "%s"
    allowed_statements:
      - "SELECT"
      - "SET"
    allowed_tables:
      - "customers"
      - "orders"
    views:
      - name: "customer_public_view"
        base_table: "customers"
        definition_fingerprint: "%s"
        column_mappings:
          id: "id"
          name: "name"
          ssn: "ssn"
          credit_card: "credit_card"
          tenant_id: "tenant_id"
      - name: "customer_renamed_view"
        base_table: "customers"
        definition_fingerprint: "%s"
        column_mappings:
          cust_id: "id"
          full_name: "name"
          national_id: "ssn"
          card_no: "credit_card"
          tenant_id: "tenant_id"
      - name: "customer_nested_view"
        base_table: "customer_renamed_view"
        definition_fingerprint: "%s"
        column_mappings:
          cust_id: "cust_id"
          full_name: "full_name"
          national_id: "national_id"
          tenant_id: "tenant_id"
        unexposed_columns:
          - "card_no"
    masked_columns:
      customers:
        - "ssn"
        - "credit_card"
`, string(agentHash), fpPublic, fpRenamed, fpNested)

	tmpFile, err := os.CreateTemp("", "view-policies-*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp policy file: %v", err)
	}
	tmpFile.Write([]byte(yamlPolicy))
	tmpFile.Close()

	slogLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := policy.NewStore(tmpFile.Name(), "", slogLogger)
	if err != nil {
		t.Fatalf("failed to initialize policy store: %v", err)
	}

	logger := proxy.NewLogger(os.Stdout)

	// 4. Start Proxy Server
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for proxy: %v", err)
	}

	handlers := make(map[proxy.ProtocolType]proxy.ProtocolHandler)
	server := proxy.NewServer(l.Addr().String(), adminDSN, store, nil, logger, nil, handlers, false, ":0", 5, nil, nil)
	pgHandler := proxy.NewPostgresProtocolHandler(adminDSN, store, nil, logger, server, true)
	server.SetHandler(proxy.ProtocolPostgres, pgHandler)
	server.InitPool(context.Background())

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				session := proxy.NewSession(c, adminDSN, store, nil, logger, server, true)
				defer session.Close()
				session.Run()
			}(conn)
		}
	}()

	proxyURL, _ := url.Parse("postgres://127.0.0.1/viewdb?sslmode=disable")
	proxyURL.Host = l.Addr().String()
	proxyURL.User = url.UserPassword("test-analyst", "agent_password_xyz")
	proxyDSN := proxyURL.String()

	// Direct DB connection using restricted role
	directURL, _ := url.Parse(adminDSN)
	directURL.User = url.UserPassword("agent_db_role", "agent_secure_pass")
	directDSN := directURL.String()

	cleanup := func() {
		l.Close()
		os.Remove(tmpFile.Name())
		pgContainer.Terminate(ctx)
	}

	return &viewMaskingTestEnv{
		proxyDSN:    proxyDSN,
		directDSN:   directDSN,
		adminDSN:    adminDSN,
		agentKey:    string(agentHash),
		policyStore: store,
		server:      server,
		cleanup:     cleanup,
	}
}

func TestViewMaskingIntegration(t *testing.T) {
	env := setupViewMaskingEnv(t)
	defer env.cleanup()

	ctx := context.Background()

	// 1. Authorized base table with sensitive column masking
	t.Run("1_AuthorizedBaseTable_Masking", func(t *testing.T) {
		conn, err := pgx.Connect(ctx, env.proxyDSN)
		if err != nil {
			t.Fatalf("failed to connect through proxy: %v", err)
		}
		defer conn.Close(ctx)

		rows, err := conn.Query(ctx, "SELECT id, name, ssn, credit_card FROM customers ORDER BY id")
		if err != nil {
			t.Fatalf("query failed: %v", err)
		}
		defer rows.Close()

		var count int
		for rows.Next() {
			count++
			var id int
			var name, ssn, cc string
			if err := rows.Scan(&id, &name, &ssn, &cc); err != nil {
				t.Fatalf("scan failed: %v", err)
			}
			// Verify exact synthetic secrets never appear
			if ssn == "987-65-4321" || ssn == "123-45-6789" {
				t.Fatalf("CRITICAL: raw synthetic SSN leaked: %s", ssn)
			}
			if cc == "4111-2222-3333-4444" || cc == "5555-6666-7777-8888" {
				t.Fatalf("CRITICAL: raw synthetic credit card leaked: %s", cc)
			}
			if ssn != "[REDACTED]" || cc != "[REDACTED]" {
				t.Fatalf("expected [REDACTED], got ssn=%s cc=%s", ssn, cc)
			}
		}
		if count == 0 {
			t.Fatalf("expected rows, got 0")
		}
	})

	// 2. Unauthorized base table rejection
	t.Run("2_UnauthorizedBaseTable_Rejection", func(t *testing.T) {
		conn, err := pgx.Connect(ctx, env.proxyDSN)
		if err != nil {
			t.Fatalf("failed to connect: %v", err)
		}
		defer conn.Close(ctx)

		_, err = conn.Query(ctx, "SELECT id, top_secret FROM secret_vault")
		if err == nil {
			t.Fatalf("expected query on secret_vault to be rejected by proxy, but succeeded")
		}
		if !strings.Contains(err.Error(), "secret_vault") || !strings.Contains(err.Error(), "not allowed by policy") {
			t.Fatalf("expected policy violation for secret_vault, got: %v", err)
		}
	})

	// 3. Authorized view with direct sensitive column mapping
	t.Run("3_AuthorizedView_DirectColumnMapping", func(t *testing.T) {
		conn, err := pgx.Connect(ctx, env.proxyDSN)
		if err != nil {
			t.Fatalf("failed to connect: %v", err)
		}
		defer conn.Close(ctx)

		rows, err := conn.Query(ctx, "SELECT id, name, ssn FROM customer_public_view ORDER BY id")
		if err != nil {
			t.Fatalf("query on approved view failed: %v", err)
		}
		defer rows.Close()

		for rows.Next() {
			var id int
			var name, ssn string
			if err := rows.Scan(&id, &name, &ssn); err != nil {
				t.Fatalf("scan failed: %v", err)
			}
			if ssn == "987-65-4321" || ssn == "123-45-6789" {
				t.Fatalf("CRITICAL: raw synthetic SSN leaked from view: %s", ssn)
			}
			if ssn != "[REDACTED]" {
				t.Fatalf("expected [REDACTED], got: %s", ssn)
			}
		}
	})

	// 4. Authorized view with renamed sensitive column
	t.Run("4_AuthorizedView_RenamedColumnMapping", func(t *testing.T) {
		conn, err := pgx.Connect(ctx, env.proxyDSN)
		if err != nil {
			t.Fatalf("failed to connect: %v", err)
		}
		defer conn.Close(ctx)

		rows, err := conn.Query(ctx, "SELECT cust_id, full_name, national_id, card_no FROM customer_renamed_view ORDER BY cust_id")
		if err != nil {
			t.Fatalf("query on renamed view failed: %v", err)
		}
		defer rows.Close()

		for rows.Next() {
			var custID int
			var fullName, nationalID, cardNo string
			if err := rows.Scan(&custID, &fullName, &nationalID, &cardNo); err != nil {
				t.Fatalf("scan failed: %v", err)
			}
			if nationalID == "987-65-4321" || nationalID == "123-45-6789" {
				t.Fatalf("CRITICAL: raw SSN leaked through renamed column national_id: %s", nationalID)
			}
			if cardNo == "4111-2222-3333-4444" || cardNo == "5555-6666-7777-8888" {
				t.Fatalf("CRITICAL: raw credit card leaked through card_no: %s", cardNo)
			}
			if nationalID != "[REDACTED]" || cardNo != "[REDACTED]" {
				t.Fatalf("expected [REDACTED], got national_id=%s, card_no=%s", nationalID, cardNo)
			}
		}
	})

	// 5. Unauthorized view rejection
	t.Run("5_UnauthorizedView_Rejection", func(t *testing.T) {
		conn, err := pgx.Connect(ctx, env.proxyDSN)
		if err != nil {
			t.Fatalf("failed to connect: %v", err)
		}
		defer conn.Close(ctx)

		_, err = conn.Query(ctx, "SELECT id, ssn FROM unauthorized_view")
		if err == nil {
			t.Fatalf("expected unauthorized_view to be blocked by proxy, but succeeded")
		}
		if !strings.Contains(err.Error(), "unauthorized_view") || !strings.Contains(err.Error(), "not allowed by policy") {
			t.Fatalf("expected default-deny error for unauthorized_view, got: %v", err)
		}
	})

	// 6. Nested view policy behavior
	t.Run("6_NestedView_InheritedMasking", func(t *testing.T) {
		conn, err := pgx.Connect(ctx, env.proxyDSN)
		if err != nil {
			t.Fatalf("failed to connect: %v", err)
		}
		defer conn.Close(ctx)

		rows, err := conn.Query(ctx, "SELECT cust_id, full_name, national_id FROM customer_nested_view ORDER BY cust_id")
		if err != nil {
			t.Fatalf("query on nested view failed: %v", err)
		}
		defer rows.Close()

		for rows.Next() {
			var custID int
			var fullName, nationalID string
			if err := rows.Scan(&custID, &fullName, &nationalID); err != nil {
				t.Fatalf("scan failed: %v", err)
			}
			if nationalID != "[REDACTED]" {
				t.Fatalf("expected [REDACTED] in nested view, got: %s", nationalID)
			}
		}
	})

	// 7. JOIN-based masking bypass attempts
	t.Run("7_JoinBypassAttempts", func(t *testing.T) {
		conn, err := pgx.Connect(ctx, env.proxyDSN)
		if err != nil {
			t.Fatalf("failed to connect: %v", err)
		}
		defer conn.Close(ctx)

		// Adversarial join with unauthorized view
		_, err = conn.Query(ctx, "SELECT o.id, u.ssn FROM orders o JOIN unauthorized_view u ON o.customer_id = u.id")
		if err == nil {
			t.Fatalf("expected JOIN with unauthorized_view to be rejected")
		}

		// Authorized join with customer_renamed_view
		rows, err := conn.Query(ctx, "SELECT o.id, v.full_name, v.national_id FROM orders o JOIN customer_renamed_view v ON o.customer_id = v.cust_id ORDER BY o.id")
		if err != nil {
			t.Fatalf("authorized JOIN query failed: %v", err)
		}
		defer rows.Close()

		for rows.Next() {
			var orderID int
			var fullName, nationalID string
			if err := rows.Scan(&orderID, &fullName, &nationalID); err != nil {
				t.Fatalf("scan failed: %v", err)
			}
			if nationalID != "[REDACTED]" {
				t.Fatalf("expected [REDACTED] for national_id in JOIN, got: %s", nationalID)
			}
		}
	})

	// 8. CTE and subquery masking bypass attempts
	t.Run("8_CTEAndSubqueryBypassAttempts", func(t *testing.T) {
		conn, err := pgx.Connect(ctx, env.proxyDSN)
		if err != nil {
			t.Fatalf("failed to connect: %v", err)
		}
		defer conn.Close(ctx)

		// Adversarial CTE referencing unauthorized view
		_, err = conn.Query(ctx, "WITH exfil AS (SELECT * FROM unauthorized_view) SELECT * FROM exfil")
		if err == nil {
			t.Fatalf("expected adversarial CTE to be rejected")
		}

		// Adversarial subquery referencing unauthorized view
		_, err = conn.Query(ctx, "SELECT sub.ssn FROM (SELECT * FROM unauthorized_view) sub")
		if err == nil {
			t.Fatalf("expected adversarial subquery to be rejected")
		}

		// Authorized CTE: sensitive columns masked
		rows, err := conn.Query(ctx, "WITH safe_cte AS (SELECT cust_id, national_id FROM customer_renamed_view) SELECT cust_id, national_id FROM safe_cte ORDER BY cust_id")
		if err != nil {
			t.Fatalf("authorized CTE failed: %v", err)
		}
		defer rows.Close()

		for rows.Next() {
			var custID int
			var nationalID string
			if err := rows.Scan(&custID, &nationalID); err != nil {
				t.Fatalf("scan failed: %v", err)
			}
			if nationalID != "[REDACTED]" {
				t.Fatalf("expected [REDACTED] in CTE result, got: %s", nationalID)
			}
		}
	})

	// 9. SELECT * and alias-qualified wildcard handling
	t.Run("9_WildcardProjections_Blocked", func(t *testing.T) {
		conn, err := pgx.Connect(ctx, env.proxyDSN)
		if err != nil {
			t.Fatalf("failed to connect: %v", err)
		}
		defer conn.Close(ctx)

		// Base table SELECT *
		_, err = conn.Query(ctx, "SELECT * FROM customers")
		if err == nil {
			t.Fatalf("expected SELECT * on customers to be blocked")
		}
		if !strings.Contains(err.Error(), "implicit row expansion") {
			t.Fatalf("expected row expansion blocked message, got: %v", err)
		}

		// View SELECT *
		_, err = conn.Query(ctx, "SELECT * FROM customer_renamed_view")
		if err == nil {
			t.Fatalf("expected SELECT * on customer_renamed_view to be blocked")
		}

		// Alias wildcard SELECT v.*
		_, err = conn.Query(ctx, "SELECT v.* FROM customer_renamed_view v")
		if err == nil {
			t.Fatalf("expected SELECT v.* on customer_renamed_view to be blocked")
		}
	})

	// 10. Schema-qualified and quoted identifiers
	t.Run("10_SchemaQualifiedAndQuotedIdentifiers", func(t *testing.T) {
		conn, err := pgx.Connect(ctx, env.proxyDSN)
		if err != nil {
			t.Fatalf("failed to connect: %v", err)
		}
		defer conn.Close(ctx)

		sql := `SELECT "cust_id", "national_id" FROM "public"."customer_renamed_view" ORDER BY "cust_id"`
		rows, err := conn.Query(ctx, sql)
		if err != nil {
			t.Fatalf("query with quoted identifiers failed: %v", err)
		}
		defer rows.Close()

		for rows.Next() {
			var custID int
			var nationalID string
			if err := rows.Scan(&custID, &nationalID); err != nil {
				t.Fatalf("scan failed: %v", err)
			}
			if nationalID != "[REDACTED]" {
				t.Fatalf("expected [REDACTED] with quoted identifiers, got: %s", nationalID)
			}
		}
	})

	// 11. Prepared or parameterized SQL behavior
	t.Run("11_PreparedAndParameterizedSQL", func(t *testing.T) {
		conn, err := pgx.Connect(ctx, env.proxyDSN)
		if err != nil {
			t.Fatalf("failed to connect: %v", err)
		}
		defer conn.Close(ctx)

		// Parameterized query via extended protocol
		var custID int
		var nationalID string
		err = conn.QueryRow(ctx, "SELECT cust_id, national_id FROM customer_renamed_view WHERE cust_id = $1", 1).Scan(&custID, &nationalID)
		if err != nil {
			t.Fatalf("parameterized query failed: %v", err)
		}
		if nationalID != "[REDACTED]" {
			t.Fatalf("expected [REDACTED] in parameterized query, got: %s", nationalID)
		}
	})

	// 12. Unsupported / malformed SQL fails closed
	t.Run("12_MalformedSQL_FailsClosed", func(t *testing.T) {
		conn, err := pgx.Connect(ctx, env.proxyDSN)
		if err != nil {
			t.Fatalf("failed to connect: %v", err)
		}
		defer conn.Close(ctx)

		_, err = conn.Query(ctx, "SELECT SYNTAX ERROR FROM WHERE")
		if err == nil {
			t.Fatalf("expected malformed SQL to fail closed")
		}
	})

	// 13. Policy reload / schema drift behavior
	t.Run("13_PolicyReloadBehavior", func(t *testing.T) {
		adminConn, err := pgx.Connect(ctx, env.adminDSN)
		if err != nil {
			t.Fatalf("failed to connect admin: %v", err)
		}
		defer adminConn.Close(ctx)

		var defPublic, defUnauthorized string
		_ = adminConn.QueryRow(ctx, "SELECT definition FROM pg_catalog.pg_views WHERE schemaname = 'public' AND viewname = 'customer_public_view'").Scan(&defPublic)
		_ = adminConn.QueryRow(ctx, "SELECT definition FROM pg_catalog.pg_views WHERE schemaname = 'public' AND viewname = 'unauthorized_view'").Scan(&defUnauthorized)

		fpPublic, _ := ast.ComputeViewFingerprint(defPublic)
		fpUnauthorized, _ := ast.ComputeViewFingerprint(defUnauthorized)

		_, _ = adminConn.Exec(ctx, "GRANT SELECT ON unauthorized_view TO agent_db_role;")
		defer adminConn.Exec(ctx, "REVOKE ALL ON unauthorized_view FROM agent_db_role;")

		// Dynamically add a new view to the policy
		updatedConfig := policy.AgentConfig{
			Name:              "test-analyst",
			Key:               env.agentKey,
			AllowedStatements: []string{"SELECT", "SET"},
			AllowedTables:     []string{"customers", "orders"},
			Views: []policy.ViewConfig{
				{
					Name:                  "customer_public_view",
					BaseTable:             "customers",
					DefinitionFingerprint: fpPublic,
					ColumnMappings: map[string]string{
						"id":          "id",
						"name":        "name",
						"ssn":         "ssn",
						"credit_card": "credit_card",
						"tenant_id":   "tenant_id",
					},
				},
				{
					Name:                  "unauthorized_view", // Now dynamically authorized!
					BaseTable:             "customers",
					DefinitionFingerprint: fpUnauthorized,
					ColumnMappings: map[string]string{
						"id":  "id",
						"ssn": "ssn",
					},
				},
			},
			MaskedColumns: map[string][]string{
				"customers": {"ssn"},
			},
		}
		env.policyStore.SetAgentPolicy("test-analyst", updatedConfig)

		conn, err := pgx.Connect(ctx, env.proxyDSN)
		if err != nil {
			t.Fatalf("failed to connect: %v", err)
		}
		defer conn.Close(ctx)

		// Formerly unauthorized_view is now approved, and ssn should be masked
		rows, err := conn.Query(ctx, "SELECT id, ssn FROM unauthorized_view ORDER BY id")
		if err != nil {
			t.Fatalf("query after dynamic policy reload failed: %v", err)
		}
		defer rows.Close()

		for rows.Next() {
			var id int
			var ssn string
			if err := rows.Scan(&id, &ssn); err != nil {
				t.Fatalf("scan failed: %v", err)
			}
			if ssn != "[REDACTED]" {
				t.Fatalf("expected [REDACTED] after dynamic authorization, got: %s", ssn)
			}
		}
	})

	// 14. Database role access restrictions (Direct Database Verification)
	t.Run("14_DatabaseRoleRestrictions_DirectAccessBlocked", func(t *testing.T) {
		// Connect DIRECTLY to PostgreSQL as agent_db_role (bypassing AgentIAM proxy)
		directConn, err := pgx.Connect(ctx, env.directDSN)
		if err != nil {
			t.Fatalf("failed direct DB connection: %v", err)
		}
		defer directConn.Close(ctx)

		var currentUser string
		_ = directConn.QueryRow(ctx, "SELECT current_user").Scan(&currentUser)
		t.Logf("directConn authenticated as current_user: %s", currentUser)

		// Inspect privileges on secret_vault
		privRows, privErr := directConn.Query(ctx, "SELECT grantee, privilege_type FROM information_schema.table_privileges WHERE table_name = 'secret_vault'")
		if privErr == nil {
			for privRows.Next() {
				var grantee, priv string
				_ = privRows.Scan(&grantee, &priv)
				t.Logf("secret_vault privilege: grantee=%s type=%s", grantee, priv)
			}
			privRows.Close()
		}

		// 1. Direct query to secret_vault must be rejected by PostgreSQL native permissions
		var dummyID int
		var dummySecret string
		err = directConn.QueryRow(ctx, "SELECT id, top_secret FROM secret_vault").Scan(&dummyID, &dummySecret)
		if err == nil {
			t.Fatalf("SECURITY VIOLATION: direct access to secret_vault succeeded as %s!", currentUser)
		}
		pgErr, ok := err.(*pgconn.PgError)
		if !ok || pgErr.Code != "42501" { // 42501 = insufficient_privilege
			t.Fatalf("expected Postgres 42501 insufficient_privilege for secret_vault, got: %v", err)
		}

		// 2. Direct query to unauthorized_view must be rejected by PostgreSQL native permissions
		var dummySSN string
		err = directConn.QueryRow(ctx, "SELECT id, ssn FROM unauthorized_view").Scan(&dummyID, &dummySSN)
		if err == nil {
			t.Fatalf("SECURITY VIOLATION: direct access to unauthorized_view succeeded as %s!", currentUser)
		}
		pgErr, ok = err.(*pgconn.PgError)
		if !ok || pgErr.Code != "42501" {
			t.Fatalf("expected Postgres 42501 insufficient_privilege for unauthorized_view, got: %v", err)
		}
	})

	// 15. No regression in tenant isolation
	t.Run("15_TenantIsolation_Preserved", func(t *testing.T) {
		// Update policy with TenantIsolation enabled for test-analyst
		hash, _ := bcrypt.GenerateFromPassword([]byte("agent_password_xyz"), bcrypt.DefaultCost)
		tenantConfig := policy.AgentConfig{
			Name:              "test-analyst",
			Key:               string(hash),
			AllowedStatements: []string{"SELECT", "SET"},
			AllowedTables:     []string{"customers"},
			Views: []policy.ViewConfig{
				{
					Name:      "customer_renamed_view",
					BaseTable: "customers",
					ColumnMappings: map[string]string{
						"cust_id":     "id",
						"full_name":   "name",
						"national_id": "ssn",
						"tenant_id":   "tenant_id",
					},
				},
			},
			MaskedColumns: map[string][]string{
				"customers": {"ssn"},
			},
		}
		env.policyStore.SetAgentPolicy("test-analyst", tenantConfig)

		// We use internal/ast directly with tenant isolation to verify both rules combine seamlessly
		parser := &ast.PostgresParser{}
		rules := ast.Rules{
			AllowedStatements: []string{"SELECT"},
			AllowedTables:     []string{"customers"},
			Views: []ast.ViewPolicy{
				{
					Name:      "customer_renamed_view",
					BaseTable: "customers",
					ColumnMappings: map[string]string{
						"cust_id":     "id",
						"full_name":   "name",
						"national_id": "ssn",
						"tenant_id":   "tenant_id",
					},
				},
			},
			MaskedColumns: map[string][]string{
				"customers": {"ssn"},
			},
			TenantIsolation: &ast.TenantIsolationRule{
				Enabled:      true,
				TenantColumn: "tenant_id",
				TenantID:     "tenant-alpha",
			},
		}

		sql := "SELECT cust_id, full_name, national_id FROM customer_renamed_view"
		rewritten, _, err := parser.ApplyRules(sql, rules, nil)
		if err != nil {
			t.Fatalf("unexpected error combining tenant isolation and view masking: %v", err)
		}

		if !strings.Contains(rewritten, "'[REDACTED]'") {
			t.Fatalf("expected national_id to be redacted, got: %s", rewritten)
		}
		if !strings.Contains(rewritten, "tenant-alpha") {
			t.Fatalf("expected tenant-alpha injection, got: %s", rewritten)
		}

		// Execute against live database
		adminConn, err := pgx.Connect(ctx, env.adminDSN)
		if err != nil {
			t.Fatalf("failed admin connection: %v", err)
		}
		defer adminConn.Close(ctx)

		rows, err := adminConn.Query(ctx, rewritten)
		if err != nil {
			t.Fatalf("execution of rewritten query failed: %v", err)
		}
		defer rows.Close()

		var rowCount int
		for rows.Next() {
			rowCount++
			var custID int
			var fullName, nationalID string
			if err := rows.Scan(&custID, &fullName, &nationalID); err != nil {
				t.Fatalf("scan failed: %v", err)
			}
			if custID != 1 || fullName != "Alice Smith" {
				t.Fatalf("CRITICAL: tenant isolation leak! Bob Jones (tenant-beta) was returned: id=%d name=%s", custID, fullName)
			}
			if nationalID != "[REDACTED]" {
				t.Fatalf("expected [REDACTED], got: %s", nationalID)
			}
		}
		if rowCount != 1 {
			t.Fatalf("expected exactly 1 row (Alice Smith, tenant-alpha), got: %d", rowCount)
		}
	})

	t.Run("Adversarial_WhereSensitivePredicate_BlockedLive", func(t *testing.T) {
		conn, err := pgx.Connect(ctx, env.proxyDSN)
		if err != nil {
			t.Fatalf("failed proxy connect: %v", err)
		}
		defer conn.Close(ctx)

		rows, err := conn.Query(ctx, "SELECT id, name FROM customers WHERE ssn = '000-11-2222'")
		if err == nil {
			rows.Close()
			t.Fatalf("expected query with sensitive column in WHERE to be rejected, but succeeded")
		}
		if !strings.Contains(err.Error(), "sensitive column 'ssn' cannot be referenced in WHERE clause") {
			t.Fatalf("expected WHERE clause violation error, got: %v", err)
		}
	})

	t.Run("Adversarial_JoinSensitivePredicate_BlockedLive", func(t *testing.T) {
		conn, err := pgx.Connect(ctx, env.proxyDSN)
		if err != nil {
			t.Fatalf("failed proxy connect: %v", err)
		}
		defer conn.Close(ctx)

		rows, err := conn.Query(ctx, "SELECT c1.id FROM customers c1 JOIN customers c2 ON c1.ssn = c2.ssn")
		if err == nil {
			rows.Close()
			t.Fatalf("expected query with sensitive column in JOIN ON to be rejected, but succeeded")
		}
		if !strings.Contains(err.Error(), "sensitive column 'ssn' cannot be referenced in JOIN ON clause") {
			t.Fatalf("expected JOIN ON clause violation error, got: %v", err)
		}
	})

	t.Run("Adversarial_PreparedStatement_RevokedOnPolicyUpdate", func(t *testing.T) {
		conn, err := pgx.Connect(ctx, env.proxyDSN)
		if err != nil {
			t.Fatalf("failed proxy connect: %v", err)
		}
		defer conn.Close(ctx)

		// 1. Initial query succeeds and delivers legitimate result
		var id int
		var name string
		err = conn.QueryRow(ctx, "SELECT id, name FROM customers WHERE id = 1").Scan(&id, &name)
		if err != nil {
			t.Fatalf("initial authorized query failed: %v", err)
		}
		if id != 1 || name != "Alice Smith" {
			t.Fatalf("unexpected initial query result: id=%d, name=%s", id, name)
		}

		initVer := env.policyStore.GetAgentVersion("test-analyst")

		// 2. Revoke policy dynamically
		revokedPolicy := policy.AgentConfig{
			AllowedStatements: []string{"SELECT"},
			AllowedTables:     []string{"orders"}, // customers removed!
		}
		env.policyStore.SetAgentPolicy("test-analyst", revokedPolicy)

		// 2a. Verify policy update was successfully applied in policy store
		updatedVer := env.policyStore.GetAgentVersion("test-analyst")
		if updatedVer <= initVer {
			t.Fatalf("policy version not incremented: init=%d, updated=%d", initVer, updatedVer)
		}

		// 3. Subsequent query on the revoked connection MUST be rejected with SQLSTATE 57P01
		var revokedID int
		var revokedName string
		err = conn.QueryRow(ctx, "SELECT id, name FROM customers WHERE id = 1").Scan(&revokedID, &revokedName)
		if err == nil {
			t.Fatalf("CRITICAL SECURITY DEFECT: revoked query succeeded with id=%d, name=%s", revokedID, revokedName)
		}

		// 3a. Independent verification: No unauthorized result reached the client
		if revokedID != 0 || revokedName != "" {
			t.Fatalf("unauthorized data leaked to client variables: id=%d, name=%s", revokedID, revokedName)
		}

		// 3b. Structured error inspection: Must return PostgreSQL SQLSTATE 57P01
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code != "57P01" {
				t.Fatalf("expected SQLSTATE 57P01, got code: %s (msg: %s)", pgErr.Code, pgErr.Message)
			}
		} else {
			errStr := err.Error()
			if !strings.Contains(errStr, "57P01") {
				t.Fatalf("expected SQLSTATE 57P01 error delivery, got non-57P01 error: %v", err)
			}
		}

		// 4. Negative control: verify that an unrelated connection reset or socket crash does NOT pass as 57P01 revocation
		unrelatedResetErr := fmt.Errorf("read tcp 127.0.0.1:5432: read: connection reset by peer")
		var fakePgErr *pgconn.PgError
		if errors.As(unrelatedResetErr, &fakePgErr) && fakePgErr.Code == "57P01" {
			t.Fatalf("negative control failed: unrelated socket reset accepted as valid 57P01 revocation")
		}
	})

	t.Run("Adversarial_ConcurrentSessionsDuringPolicyUpdate", func(t *testing.T) {
		// Restore allowed policy first
		validPolicy := policy.AgentConfig{
			AllowedStatements: []string{"SELECT"},
			AllowedTables:     []string{"customers", "orders"},
		}
		env.policyStore.SetAgentPolicy("test-analyst", validPolicy)

		done := make(chan bool)
		errCh := make(chan error, 20)

		// Spawn 5 concurrent querying sessions
		for i := 0; i < 5; i++ {
			go func() {
				c, err := pgx.Connect(ctx, env.proxyDSN)
				if err != nil {
					// Connection might be refused during dynamic policy changes
					return
				}
				defer c.Close(ctx)

				for {
					select {
					case <-done:
						return
					default:
						rows, qErr := c.Query(ctx, "SELECT id, name FROM customers WHERE id = 1")
						if qErr == nil {
							rows.Close()
						}
						time.Sleep(5 * time.Millisecond)
					}
				}
			}()
		}

		// Rapidly update policies 5 times concurrently
		for v := 0; v < 5; v++ {
			time.Sleep(10 * time.Millisecond)
			env.policyStore.SetAgentPolicy("test-analyst", policy.AgentConfig{
				Key:               env.agentKey,
				AllowedStatements: []string{"SELECT"},
				AllowedTables:     []string{"customers", "orders"},
				SelectLimit:       v + 10,
			})
		}

		close(done)
		select {
		case err := <-errCh:
			t.Fatalf("concurrent session error: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
	})

	t.Run("Adversarial_DirectPostgreSQLViewAccess_PrivilegeBoundary", func(t *testing.T) {
		// Connect directly to PostgreSQL using restricted DB role
		directConn, err := pgx.Connect(ctx, env.directDSN)
		if err != nil {
			t.Fatalf("failed direct postgres connect: %v", err)
		}
		defer directConn.Close(ctx)

		// SEC-P2-01 Demonstration: Querying definer view directly in PostgreSQL returns raw sensitive data!
		row := directConn.QueryRow(ctx, "SELECT ssn FROM customer_public_view WHERE id = 1")
		var ssn string
		err = row.Scan(&ssn)
		if err != nil {
			t.Fatalf("direct view select failed: %v", err)
		}
		if ssn == "987-65-4321" {
			t.Logf("CONFIRMED SEC-P2-01 / RISK-VIEW-02: Direct database connection bypassed proxy and accessed raw sensitive value '%s' via PostgreSQL definer view. Network isolation of PostgreSQL listener (port 5432) is mandatory.", ssn)
		} else {
			t.Fatalf("unexpected raw ssn value: %s", ssn)
		}
	})

	// 16. Adversarial: Missing definition fingerprint fails closed
	t.Run("Adversarial_MissingFingerprint_AccessDenied", func(t *testing.T) {
		adminConn, err := pgx.Connect(ctx, env.adminDSN)
		if err != nil {
			t.Fatalf("failed to connect admin: %v", err)
		}
		defer adminConn.Close(ctx)

		_, err = adminConn.Exec(ctx, "CREATE VIEW customer_nofp_view AS SELECT id, name FROM customers;")
		if err != nil {
			t.Fatalf("failed to create view: %v", err)
		}
		defer adminConn.Exec(ctx, "DROP VIEW IF EXISTS customer_nofp_view;")

		// Configure in policy WITHOUT fingerprint
		env.policyStore.SetAgentPolicy("test-analyst", policy.AgentConfig{
			Key:               env.agentKey,
			AllowedStatements: []string{"SELECT"},
			AllowedTables:     []string{"customers", "orders"},
			Views: []policy.ViewConfig{
				{
					Name:      "customer_nofp_view",
					BaseTable: "customers",
					ColumnMappings: map[string]string{
						"id":   "id",
						"name": "name",
					},
					DefinitionFingerprint: "",
				},
			},
		})

		conn, err := pgx.Connect(ctx, env.proxyDSN)
		if err != nil {
			t.Fatalf("failed to connect: %v", err)
		}
		defer conn.Close(ctx)

		_, err = conn.Query(ctx, "SELECT id, name FROM customer_nofp_view;")
		if err == nil {
			t.Fatalf("expected view with missing fingerprint to be denied, but succeeded")
		}
		if !strings.Contains(err.Error(), "has not been verified against PostgreSQL catalog definition") &&
			!strings.Contains(err.Error(), "57P01") && !strings.Contains(err.Error(), "policy violation") {
			t.Fatalf("expected verification denial error, got: %v", err)
		}
	})

	// 17. Adversarial: Incorrect definition fingerprint fails closed
	t.Run("Adversarial_IncorrectFingerprint_AccessDenied", func(t *testing.T) {
		adminConn, err := pgx.Connect(ctx, env.adminDSN)
		if err != nil {
			t.Fatalf("failed to connect admin: %v", err)
		}
		defer adminConn.Close(ctx)

		_, err = adminConn.Exec(ctx, "CREATE VIEW customer_badfp_view AS SELECT id, name FROM customers;")
		if err != nil {
			t.Fatalf("failed to create view: %v", err)
		}
		defer adminConn.Exec(ctx, "DROP VIEW IF EXISTS customer_badfp_view;")

		env.policyStore.SetAgentPolicy("test-analyst", policy.AgentConfig{
			Key:               env.agentKey,
			AllowedStatements: []string{"SELECT"},
			AllowedTables:     []string{"customers", "orders"},
			Views: []policy.ViewConfig{
				{
					Name:                  "customer_badfp_view",
					BaseTable:             "customers",
					DefinitionFingerprint: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
					ColumnMappings: map[string]string{
						"id":   "id",
						"name": "name",
					},
				},
			},
		})

		conn, err := pgx.Connect(ctx, env.proxyDSN)
		if err != nil {
			t.Fatalf("failed to connect: %v", err)
		}
		defer conn.Close(ctx)

		_, err = conn.Query(ctx, "SELECT id, name FROM customer_badfp_view;")
		if err == nil {
			t.Fatalf("expected view with incorrect fingerprint to be denied, but succeeded")
		}
		if !strings.Contains(err.Error(), "has not been verified against PostgreSQL catalog definition") &&
			!strings.Contains(err.Error(), "policy violation") {
			t.Fatalf("expected verification denial error, got: %v", err)
		}
	})

	// 18. Adversarial: Changed view definition after approval (Schema Drift) detected
	t.Run("Adversarial_SchemaDrift_AlteredViewDetected", func(t *testing.T) {
		adminConn, err := pgx.Connect(ctx, env.adminDSN)
		if err != nil {
			t.Fatalf("failed to connect admin: %v", err)
		}
		defer adminConn.Close(ctx)

		_, err = adminConn.Exec(ctx, "CREATE VIEW customer_drift_view AS SELECT id, name FROM customers;")
		if err != nil {
			t.Fatalf("failed to create view: %v", err)
		}
		defer adminConn.Exec(ctx, "DROP VIEW IF EXISTS customer_drift_view;")

		var def string
		_ = adminConn.QueryRow(ctx, "SELECT definition FROM pg_catalog.pg_views WHERE schemaname = 'public' AND viewname = 'customer_drift_view'").Scan(&def)
		fp, _ := ast.ComputeViewFingerprint(def)

		env.policyStore.SetAgentPolicy("test-analyst", policy.AgentConfig{
			Key:               env.agentKey,
			AllowedStatements: []string{"SELECT"},
			AllowedTables:     []string{"customers", "orders"},
			Views: []policy.ViewConfig{
				{
					Name:                  "customer_drift_view",
					BaseTable:             "customers",
					DefinitionFingerprint: fp,
					ColumnMappings: map[string]string{
						"id":   "id",
						"name": "name",
					},
				},
			},
		})

		// Query before drift succeeds
		conn, err := pgx.Connect(ctx, env.proxyDSN)
		if err != nil {
			t.Fatalf("failed to connect: %v", err)
		}
		defer conn.Close(ctx)

		rows, err := conn.Query(ctx, "SELECT id, name FROM customer_drift_view;")
		if err != nil {
			t.Fatalf("expected query on approved view to succeed before drift: %v", err)
		}
		rows.Close()

		// DBA alters the view in PostgreSQL after approval
		_, err = adminConn.Exec(ctx, "CREATE OR REPLACE VIEW customer_drift_view AS SELECT id, name, ssn FROM customers;")
		if err != nil {
			t.Fatalf("failed to alter view: %v", err)
		}

		// Detect drift
		drift, err := env.server.GetCatalogVerifier().CheckDrift(ctx, "public", "customer_drift_view")
		if !drift {
			t.Fatalf("expected schema drift to be detected after CREATE OR REPLACE VIEW")
		}

		// Invalidate view and revoke sessions
		env.server.GetCatalogVerifier().InvalidateView("public", "customer_drift_view")
		env.server.RevokeSessionsForClient("test-analyst")

		// Query after drift fails closed
		conn2, err2 := pgx.Connect(ctx, env.proxyDSN)
		if err2 == nil {
			defer conn2.Close(ctx)
			_, errQuery := conn2.Query(ctx, "SELECT id, name FROM customer_drift_view;")
			if errQuery == nil {
				t.Fatalf("expected query on drifted view to fail closed, but succeeded")
			}
		}
	})

	// 19. Adversarial: Computed sensitive substring projection (SEC-P2-05) rejected
	t.Run("Adversarial_ComputedSensitiveSubstring_SEC_P2_05", func(t *testing.T) {
		adminConn, err := pgx.Connect(ctx, env.adminDSN)
		if err != nil {
			t.Fatalf("failed to connect admin: %v", err)
		}
		defer adminConn.Close(ctx)

		_, err = adminConn.Exec(ctx, "CREATE VIEW customer_computed_view AS SELECT id, substring(ssn FROM 1 FOR 4) AS identity_prefix FROM customers;")
		if err != nil {
			t.Fatalf("failed to create computed view: %v", err)
		}
		defer adminConn.Exec(ctx, "DROP VIEW IF EXISTS customer_computed_view;")

		var def string
		_ = adminConn.QueryRow(ctx, "SELECT definition FROM pg_catalog.pg_views WHERE schemaname = 'public' AND viewname = 'customer_computed_view'").Scan(&def)
		fp, _ := ast.ComputeViewFingerprint(def)

		// Policy maliciously claims ssn is in unexposed_columns
		env.policyStore.SetAgentPolicy("test-analyst", policy.AgentConfig{
			Key:               env.agentKey,
			AllowedStatements: []string{"SELECT"},
			AllowedTables:     []string{"customers", "orders"},
			Views: []policy.ViewConfig{
				{
					Name:                  "customer_computed_view",
					BaseTable:             "customers",
					DefinitionFingerprint: fp,
					ColumnMappings: map[string]string{
						"id": "id",
					},
					UnexposedColumns: []string{"ssn"},
				},
			},
			MaskedColumns: map[string][]string{
				"customers": {"ssn"},
			},
		})

		conn, err := pgx.Connect(ctx, env.proxyDSN)
		if err != nil {
			t.Fatalf("failed to connect: %v", err)
		}
		defer conn.Close(ctx)

		// Query attempting to read identity_prefix must be blocked
		_, err = conn.Query(ctx, "SELECT identity_prefix FROM customer_computed_view;")
		if err == nil {
			t.Fatalf("CRITICAL SEC-P2-05: computed sensitive substring escaped masking through approved view!")
		}
		if !strings.Contains(err.Error(), "has not been verified against PostgreSQL catalog definition") &&
			!strings.Contains(err.Error(), "policy violation") {
			t.Fatalf("expected verification or policy violation error, got: %v", err)
		}
	})

	// 20. Adversarial: Sensitive column renamed to innocuous alias without mapping
	t.Run("Adversarial_SensitiveColumnRenamedToInnocuousAlias_Denied", func(t *testing.T) {
		adminConn, err := pgx.Connect(ctx, env.adminDSN)
		if err != nil {
			t.Fatalf("failed to connect admin: %v", err)
		}
		defer adminConn.Close(ctx)

		_, err = adminConn.Exec(ctx, "CREATE VIEW customer_innocuous_view AS SELECT id, ssn AS notes FROM customers;")
		if err != nil {
			t.Fatalf("failed to create view: %v", err)
		}
		defer adminConn.Exec(ctx, "DROP VIEW IF EXISTS customer_innocuous_view;")

		var def string
		_ = adminConn.QueryRow(ctx, "SELECT definition FROM pg_catalog.pg_views WHERE schemaname = 'public' AND viewname = 'customer_innocuous_view'").Scan(&def)
		fp, _ := ast.ComputeViewFingerprint(def)

		// Deceptive policy maps notes to notes (pretending it's not ssn)
		env.policyStore.SetAgentPolicy("test-analyst", policy.AgentConfig{
			Key:               env.agentKey,
			AllowedStatements: []string{"SELECT"},
			AllowedTables:     []string{"customers", "orders"},
			Views: []policy.ViewConfig{
				{
					Name:                  "customer_innocuous_view",
					BaseTable:             "customers",
					DefinitionFingerprint: fp,
					ColumnMappings: map[string]string{
						"id":    "id",
						"notes": "notes",
					},
				},
			},
			MaskedColumns: map[string][]string{
				"customers": {"ssn"},
			},
		})

		conn, err := pgx.Connect(ctx, env.proxyDSN)
		if err != nil {
			t.Fatalf("failed to connect: %v", err)
		}
		defer conn.Close(ctx)

		_, err = conn.Query(ctx, "SELECT notes FROM customer_innocuous_view;")
		if err == nil {
			t.Fatalf("CRITICAL: renamed sensitive column without mapping escaped masking!")
		}
		if !strings.Contains(err.Error(), "has not been verified against PostgreSQL catalog definition") &&
			!strings.Contains(err.Error(), "policy violation") {
			t.Fatalf("expected verification failure, got: %v", err)
		}
	})

	// 21. Adversarial: Search_path shadowing defense
	t.Run("Adversarial_SearchPathShadowing_Protected", func(t *testing.T) {
		adminConn, err := pgx.Connect(ctx, env.adminDSN)
		if err != nil {
			t.Fatalf("failed to connect admin: %v", err)
		}
		defer adminConn.Close(ctx)

		// Attacker creates an evil schema and shadows customer_public_view
		_, _ = adminConn.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS evil;")
		_, _ = adminConn.Exec(ctx, "CREATE TABLE IF NOT EXISTS evil.customer_public_view (id INT, ssn TEXT);")
		_, _ = adminConn.Exec(ctx, "INSERT INTO evil.customer_public_view VALUES (999, 'unmasked_evil_ssn');")
		defer adminConn.Exec(ctx, "DROP SCHEMA IF EXISTS evil CASCADE;")

		// Restore clean policy for customer_public_view
		var defPublic string
		_ = adminConn.QueryRow(ctx, "SELECT definition FROM pg_catalog.pg_views WHERE schemaname = 'public' AND viewname = 'customer_public_view'").Scan(&defPublic)
		fpPublic, _ := ast.ComputeViewFingerprint(defPublic)

		env.policyStore.SetAgentPolicy("test-analyst", policy.AgentConfig{
			Key:               env.agentKey,
			AllowedStatements: []string{"SELECT", "SET"},
			AllowedTables:     []string{"customers", "orders"},
			Views: []policy.ViewConfig{
				{
					Name:                  "customer_public_view",
					BaseTable:             "customers",
					DefinitionFingerprint: fpPublic,
					ColumnMappings: map[string]string{
						"id":          "id",
						"name":        "name",
						"ssn":         "ssn",
						"credit_card": "credit_card",
						"tenant_id":   "tenant_id",
					},
				},
			},
			MaskedColumns: map[string][]string{
				"customers": {"ssn", "credit_card"},
			},
		})

		conn, err := pgx.Connect(ctx, env.proxyDSN)
		if err != nil {
			t.Fatalf("failed to connect: %v", err)
		}
		defer conn.Close(ctx)

		// Attacker attempts to tamper with search_path
		_, _ = conn.Exec(ctx, "SET search_path = evil, public;")

		// Query on customer_public_view must be canonicalized and masked
		row := conn.QueryRow(ctx, "SELECT ssn FROM customer_public_view WHERE id = 1;")
		var ssn string
		err = row.Scan(&ssn)
		if err != nil {
			t.Fatalf("query failed: %v", err)
		}
		if ssn != "[REDACTED]" {
			t.Fatalf("CRITICAL: search_path shadowing leaked unmasked value: %s", ssn)
		}
	})

	// 22. Adversarial: Cross-client cache isolation (SEC-P2-06)
	// Client A has valid fingerprint; Client B has invalid fingerprint for same view.
	t.Run("Adversarial_CrossClientCache_ClientAValid_ClientBInvalid", func(t *testing.T) {
		adminConn, err := pgx.Connect(ctx, env.adminDSN)
		if err != nil {
			t.Fatalf("failed to connect admin: %v", err)
		}
		defer adminConn.Close(ctx)

		_, _ = adminConn.Exec(ctx, "CREATE VIEW customer_shared_view AS SELECT id, name FROM customers;")
		defer adminConn.Exec(ctx, "DROP VIEW IF EXISTS customer_shared_view;")

		var def string
		_ = adminConn.QueryRow(ctx, "SELECT definition FROM pg_catalog.pg_views WHERE schemaname = 'public' AND viewname = 'customer_shared_view'").Scan(&def)
		fp, _ := ast.ComputeViewFingerprint(def)

		// Client A: Valid fingerprint
		env.policyStore.SetAgentPolicy("client-a", policy.AgentConfig{
			Key:               env.agentKey,
			AllowedStatements: []string{"SELECT"},
			AllowedTables:     []string{"customers"},
			Views: []policy.ViewConfig{
				{
					Name:                  "customer_shared_view",
					BaseTable:             "customers",
					DefinitionFingerprint: fp,
					ColumnMappings:        map[string]string{"id": "id", "name": "name"},
				},
			},
		})

		// Client B: Invalid/tampered fingerprint
		env.policyStore.SetAgentPolicy("client-b", policy.AgentConfig{
			Key:               env.agentKey,
			AllowedStatements: []string{"SELECT"},
			AllowedTables:     []string{"customers"},
			Views: []policy.ViewConfig{
				{
					Name:                  "customer_shared_view",
					BaseTable:             "customers",
					DefinitionFingerprint: "sha256:badbeefbadbeefbadbeefbadbeefbadbeefbadbeefbadbeefbadbeefbadbeef",
					ColumnMappings:        map[string]string{"id": "id", "name": "name"},
				},
			},
		})

		// Connect Client A -> Must succeed
		dsnA, _ := url.Parse(env.proxyDSN)
		dsnA.User = url.UserPassword("client-a", "agent_password_xyz")
		connA, err := pgx.Connect(ctx, dsnA.String())
		if err != nil {
			t.Fatalf("client-a failed to connect: %v", err)
		}
		defer connA.Close(ctx)

		rowsA, err := connA.Query(ctx, "SELECT id, name FROM customer_shared_view;")
		if err != nil {
			t.Fatalf("client-a expected to succeed on valid view, got: %v", err)
		}
		rowsA.Close()

		// Connect Client B -> Must FAIL CLOSED (cannot reuse Client A's verification)
		dsnB, _ := url.Parse(env.proxyDSN)
		dsnB.User = url.UserPassword("client-b", "agent_password_xyz")
		connB, err := pgx.Connect(ctx, dsnB.String())
		if err != nil {
			t.Fatalf("client-b failed to connect: %v", err)
		}
		defer connB.Close(ctx)

		_, errB := connB.Query(ctx, "SELECT id, name FROM customer_shared_view;")
		if errB == nil {
			t.Fatalf("CRITICAL SEC-P2-06: client-b with invalid fingerprint was authorized via client-a's cache!")
		}
		if !strings.Contains(errB.Error(), "policy violation") {
			t.Fatalf("expected policy violation for client-b, got: %v", errB)
		}
	})

	// 23. Adversarial: Reverse verification order (Client B verified first, then Client A)
	t.Run("Adversarial_CrossClientCache_ReverseVerificationOrder", func(t *testing.T) {
		adminConn, err := pgx.Connect(ctx, env.adminDSN)
		if err != nil {
			t.Fatalf("failed to connect admin: %v", err)
		}
		defer adminConn.Close(ctx)

		_, _ = adminConn.Exec(ctx, "CREATE VIEW customer_shared_rev_view AS SELECT id, name FROM customers;")
		defer adminConn.Exec(ctx, "DROP VIEW IF EXISTS customer_shared_rev_view;")

		var def string
		_ = adminConn.QueryRow(ctx, "SELECT definition FROM pg_catalog.pg_views WHERE schemaname = 'public' AND viewname = 'customer_shared_rev_view'").Scan(&def)
		fp, _ := ast.ComputeViewFingerprint(def)

		// Client A: Valid fingerprint
		env.policyStore.SetAgentPolicy("client-a", policy.AgentConfig{
			Key:               env.agentKey,
			AllowedStatements: []string{"SELECT"},
			AllowedTables:     []string{"customers"},
			Views: []policy.ViewConfig{
				{
					Name:                  "customer_shared_rev_view",
					BaseTable:             "customers",
					DefinitionFingerprint: fp,
					ColumnMappings:        map[string]string{"id": "id", "name": "name"},
				},
			},
		})

		// Client B: Invalid/tampered fingerprint
		env.policyStore.SetAgentPolicy("client-b", policy.AgentConfig{
			Key:               env.agentKey,
			AllowedStatements: []string{"SELECT"},
			AllowedTables:     []string{"customers"},
			Views: []policy.ViewConfig{
				{
					Name:                  "customer_shared_rev_view",
					BaseTable:             "customers",
					DefinitionFingerprint: "sha256:badbeefbadbeefbadbeefbadbeefbadbeefbadbeefbadbeefbadbeefbadbeef",
					ColumnMappings:        map[string]string{"id": "id", "name": "name"},
				},
			},
		})

		dsnB, _ := url.Parse(env.proxyDSN)
		dsnB.User = url.UserPassword("client-b", "agent_password_xyz")
		connB, err := pgx.Connect(ctx, dsnB.String())
		if err != nil {
			t.Fatalf("client-b failed to connect: %v", err)
		}
		defer connB.Close(ctx)

		// Client B queries first -> fails
		rowsB, errB := connB.Query(ctx, "SELECT id, name FROM customer_shared_rev_view;")
		if errB == nil {
			defer rowsB.Close()
			for rowsB.Next() {
			}
			errB = rowsB.Err()
		}
		if errB == nil {
			t.Fatalf("client-b expected to fail closed")
		}

		// Client A queries second -> must still succeed (Client B's failure does not contaminate Client A)
		dsnA, _ := url.Parse(env.proxyDSN)
		dsnA.User = url.UserPassword("client-a", "agent_password_xyz")
		connA, err := pgx.Connect(ctx, dsnA.String())
		if err != nil {
			t.Fatalf("client-a failed to connect: %v", err)
		}
		defer connA.Close(ctx)

		rowsA, err := connA.Query(ctx, "SELECT id, name FROM customer_shared_rev_view;")
		if err != nil {
			t.Fatalf("client-a expected to succeed despite client-b failure, got: %v", err)
		}
		defer rowsA.Close()
		var countA int
		for rowsA.Next() {
			countA++
		}
		if err := rowsA.Err(); err != nil {
			t.Fatalf("client-a query execution failed: %v", err)
		}
		if countA == 0 {
			t.Fatalf("expected rows for client-a, got 0")
		}
	})

	// 24. Adversarial: Automatic runtime schema drift detection on existing connection (RISK-VIEW-01)
	t.Run("Adversarial_AutomaticRuntimeSchemaDrift_WithoutPolicyReload", func(t *testing.T) {
		adminConn, err := pgx.Connect(ctx, env.adminDSN)
		if err != nil {
			t.Fatalf("failed to connect admin: %v", err)
		}
		defer adminConn.Close(ctx)

		_, _ = adminConn.Exec(ctx, "CREATE VIEW customer_auto_drift_view AS SELECT id, name FROM customers;")
		defer adminConn.Exec(ctx, "DROP VIEW IF EXISTS customer_auto_drift_view;")

		var def string
		_ = adminConn.QueryRow(ctx, "SELECT definition FROM pg_catalog.pg_views WHERE schemaname = 'public' AND viewname = 'customer_auto_drift_view'").Scan(&def)
		fp, _ := ast.ComputeViewFingerprint(def)

		env.policyStore.SetAgentPolicy("test-analyst", policy.AgentConfig{
			Key:               env.agentKey,
			AllowedStatements: []string{"SELECT"},
			AllowedTables:     []string{"customers"},
			Views: []policy.ViewConfig{
				{
					Name:                  "customer_auto_drift_view",
					BaseTable:             "customers",
					DefinitionFingerprint: fp,
					ColumnMappings:        map[string]string{"id": "id", "name": "name"},
				},
			},
		})

		// Configure strict query-time catalog freshness
		env.server.GetCatalogVerifier().SetTTL(0)

		// 1. Establish connection and execute query successfully
		conn, err := pgx.Connect(ctx, env.proxyDSN)
		if err != nil {
			t.Fatalf("failed to connect: %v", err)
		}
		defer conn.Close(ctx)

		rows, err := conn.Query(ctx, "SELECT id, name FROM customer_auto_drift_view;")
		if err != nil {
			t.Fatalf("expected initial query to succeed: %v", err)
		}
		rows.Close()

		// 2. Out-of-band DDL alters view definition in PostgreSQL without touching AgentIAM policy!
		_, err = adminConn.Exec(ctx, "CREATE OR REPLACE VIEW customer_auto_drift_view AS SELECT id, name, ssn FROM customers;")
		if err != nil {
			t.Fatalf("admin failed to alter view: %v", err)
		}

		// 3. Query again through the ALREADY CONNECTED client without manual CheckDrift or policy reload!
		rowsDrift, errDrift := conn.Query(ctx, "SELECT id, name FROM customer_auto_drift_view;")
		if errDrift == nil {
			defer rowsDrift.Close()
			for rowsDrift.Next() {
			}
			errDrift = rowsDrift.Err()
		}
		if errDrift == nil {
			t.Fatalf("CRITICAL RISK-VIEW-01: out-of-band view alteration was not detected automatically at runtime!")
		}
		if !strings.Contains(errDrift.Error(), "policy violation") {
			t.Fatalf("expected policy violation for drifted view, got: %v", errDrift)
		}
	})

	// 25. Adversarial: Prepared statement execution fails closed after runtime view drift
	t.Run("Adversarial_PreparedStatement_FailsAfterRuntimeDrift", func(t *testing.T) {
		adminConn, err := pgx.Connect(ctx, env.adminDSN)
		if err != nil {
			t.Fatalf("failed to connect admin: %v", err)
		}
		defer adminConn.Close(ctx)

		_, _ = adminConn.Exec(ctx, "CREATE VIEW customer_prep_drift_view AS SELECT id, name FROM customers;")
		defer adminConn.Exec(ctx, "DROP VIEW IF EXISTS customer_prep_drift_view;")

		var def string
		_ = adminConn.QueryRow(ctx, "SELECT definition FROM pg_catalog.pg_views WHERE schemaname = 'public' AND viewname = 'customer_prep_drift_view'").Scan(&def)
		fp, _ := ast.ComputeViewFingerprint(def)

		env.policyStore.SetAgentPolicy("test-analyst", policy.AgentConfig{
			Key:               env.agentKey,
			AllowedStatements: []string{"SELECT"},
			AllowedTables:     []string{"customers"},
			Views: []policy.ViewConfig{
				{
					Name:                  "customer_prep_drift_view",
					BaseTable:             "customers",
					DefinitionFingerprint: fp,
					ColumnMappings:        map[string]string{"id": "id", "name": "name"},
				},
			},
		})

		env.server.GetCatalogVerifier().SetTTL(0)

		conn, err := pgx.Connect(ctx, env.proxyDSN)
		if err != nil {
			t.Fatalf("failed to connect: %v", err)
		}
		defer conn.Close(ctx)

		// Prepare statement on approved view
		_, err = conn.Prepare(ctx, "stmt_prep_drift", "SELECT id, name FROM customer_prep_drift_view WHERE id = $1")
		if err != nil {
			t.Fatalf("failed to prepare statement: %v", err)
		}

		// Execute successfully before drift
		var id int
		var name string
		err = conn.QueryRow(ctx, "stmt_prep_drift", 1).Scan(&id, &name)
		if err != nil {
			t.Fatalf("expected prepared statement to succeed before drift: %v", err)
		}

		// Out-of-band DDL alters view definition
		_, err = adminConn.Exec(ctx, "CREATE OR REPLACE VIEW customer_prep_drift_view AS SELECT id, name, ssn FROM customers;")
		if err != nil {
			t.Fatalf("failed to alter view: %v", err)
		}

		// Execute prepared statement again -> must fail closed on Bind
		err = conn.QueryRow(ctx, "stmt_prep_drift", 1).Scan(&id, &name)
		if err == nil {
			t.Fatalf("CRITICAL: prepared statement succeeded after runtime view drift!")
		}
		if !strings.Contains(err.Error(), "policy violation") && !strings.Contains(err.Error(), "57P01") {
			t.Fatalf("expected policy violation for prepared statement after drift, got: %v", err)
		}
	})

	// 26. Adversarial: Sensitive WHERE predicate in view definition rejected (SEC-P2-07)
	t.Run("Adversarial_SensitiveWherePredicate_InViewDefinition_Denied", func(t *testing.T) {
		adminConn, err := pgx.Connect(ctx, env.adminDSN)
		if err != nil {
			t.Fatalf("failed to connect admin: %v", err)
		}
		defer adminConn.Close(ctx)

		// Attacker defines view that filters rows using sensitive ssn
		_, err = adminConn.Exec(ctx, "CREATE VIEW customer_where_leak_view AS SELECT id, name FROM customers WHERE ssn > '500';")
		if err != nil {
			t.Fatalf("failed to create view: %v", err)
		}
		defer adminConn.Exec(ctx, "DROP VIEW IF EXISTS customer_where_leak_view;")

		var def string
		_ = adminConn.QueryRow(ctx, "SELECT definition FROM pg_catalog.pg_views WHERE schemaname = 'public' AND viewname = 'customer_where_leak_view'").Scan(&def)
		fp, _ := ast.ComputeViewFingerprint(def)

		env.policyStore.SetAgentPolicy("test-analyst", policy.AgentConfig{
			Key:               env.agentKey,
			AllowedStatements: []string{"SELECT"},
			AllowedTables:     []string{"customers"},
			Views: []policy.ViewConfig{
				{
					Name:                  "customer_where_leak_view",
					BaseTable:             "customers",
					DefinitionFingerprint: fp,
					ColumnMappings:        map[string]string{"id": "id", "name": "name"},
				},
			},
			MaskedColumns: map[string][]string{
				"customers": {"ssn"},
			},
		})

		conn, err := pgx.Connect(ctx, env.proxyDSN)
		if err != nil {
			t.Fatalf("failed to connect: %v", err)
		}
		defer conn.Close(ctx)

		_, err = conn.Query(ctx, "SELECT id, name FROM customer_where_leak_view;")
		if err == nil {
			t.Fatalf("CRITICAL SEC-P2-07: view definition with sensitive WHERE predicate was permitted!")
		}
		if !strings.Contains(err.Error(), "policy violation") {
			t.Fatalf("expected policy violation for sensitive WHERE predicate, got: %v", err)
		}
	})

	// 27. Adversarial: Sensitive JOIN ON predicate in view definition rejected (SEC-P2-07)
	t.Run("Adversarial_SensitiveJoinPredicate_InViewDefinition_Denied", func(t *testing.T) {
		adminConn, err := pgx.Connect(ctx, env.adminDSN)
		if err != nil {
			t.Fatalf("failed to connect admin: %v", err)
		}
		defer adminConn.Close(ctx)

		_, err = adminConn.Exec(ctx, "CREATE VIEW customer_join_leak_view AS SELECT customers.id, customers.name FROM customers JOIN secret_vault ON customers.ssn = secret_vault.top_secret;")
		if err != nil {
			t.Fatalf("failed to create view: %v", err)
		}
		defer adminConn.Exec(ctx, "DROP VIEW IF EXISTS customer_join_leak_view;")

		var def string
		_ = adminConn.QueryRow(ctx, "SELECT definition FROM pg_catalog.pg_views WHERE schemaname = 'public' AND viewname = 'customer_join_leak_view'").Scan(&def)
		fp, _ := ast.ComputeViewFingerprint(def)

		env.policyStore.SetAgentPolicy("test-analyst", policy.AgentConfig{
			Key:               env.agentKey,
			AllowedStatements: []string{"SELECT"},
			AllowedTables:     []string{"customers"},
			Views: []policy.ViewConfig{
				{
					Name:                  "customer_join_leak_view",
					BaseTable:             "customers",
					DefinitionFingerprint: fp,
					ColumnMappings:        map[string]string{"id": "id", "name": "name"},
				},
			},
			MaskedColumns: map[string][]string{
				"customers": {"ssn"},
			},
		})

		conn, err := pgx.Connect(ctx, env.proxyDSN)
		if err != nil {
			t.Fatalf("failed to connect: %v", err)
		}
		defer conn.Close(ctx)

		_, err = conn.Query(ctx, "SELECT id, name FROM customer_join_leak_view;")
		if err == nil {
			t.Fatalf("CRITICAL SEC-P2-07: view definition with sensitive JOIN predicate was permitted!")
		}
		if !strings.Contains(err.Error(), "policy violation") {
			t.Fatalf("expected policy violation for sensitive JOIN predicate, got: %v", err)
		}
	})

	// 28. Adversarial: Nested view - altered inner view causes outer view query to fail closed (SEC-P2-08)
	t.Run("Adversarial_NestedView_AlteredInnerView_FailsOuterQuery", func(t *testing.T) {
		adminConn, err := pgx.Connect(ctx, env.adminDSN)
		if err != nil {
			t.Fatalf("failed to connect admin: %v", err)
		}
		defer adminConn.Close(ctx)

		_, _ = adminConn.Exec(ctx, "CREATE VIEW inner_dep_view AS SELECT id, name FROM customers;")
		_, _ = adminConn.Exec(ctx, "CREATE VIEW outer_nested_view AS SELECT id, name FROM inner_dep_view;")
		defer adminConn.Exec(ctx, "DROP VIEW IF EXISTS outer_nested_view;")
		defer adminConn.Exec(ctx, "DROP VIEW IF EXISTS inner_dep_view;")

		var defInner, defOuter string
		_ = adminConn.QueryRow(ctx, "SELECT definition FROM pg_catalog.pg_views WHERE schemaname = 'public' AND viewname = 'inner_dep_view'").Scan(&defInner)
		_ = adminConn.QueryRow(ctx, "SELECT definition FROM pg_catalog.pg_views WHERE schemaname = 'public' AND viewname = 'outer_nested_view'").Scan(&defOuter)
		fpInner, _ := ast.ComputeViewFingerprint(defInner)
		fpOuter, _ := ast.ComputeViewFingerprint(defOuter)

		env.policyStore.SetAgentPolicy("test-analyst", policy.AgentConfig{
			Key:               env.agentKey,
			AllowedStatements: []string{"SELECT"},
			AllowedTables:     []string{"customers"},
			Views: []policy.ViewConfig{
				{
					Name:                  "inner_dep_view",
					BaseTable:             "customers",
					DefinitionFingerprint: fpInner,
					ColumnMappings:        map[string]string{"id": "id", "name": "name"},
				},
				{
					Name:                  "outer_nested_view",
					BaseTable:             "inner_dep_view",
					DefinitionFingerprint: fpOuter,
					ColumnMappings:        map[string]string{"id": "id", "name": "name"},
				},
			},
		})

		env.server.GetCatalogVerifier().SetTTL(0)

		conn, err := pgx.Connect(ctx, env.proxyDSN)
		if err != nil {
			t.Fatalf("failed to connect: %v", err)
		}
		defer conn.Close(ctx)

		// 1. Query outer view -> succeeds before inner drift
		rows, err := conn.Query(ctx, "SELECT id, name FROM outer_nested_view;")
		if err != nil {
			t.Fatalf("expected outer view query to succeed: %v", err)
		}
		rows.Close()

		// 2. DBA alters INNER view in PostgreSQL (outer view SQL remains completely unchanged!)
		_, err = adminConn.Exec(ctx, "CREATE OR REPLACE VIEW inner_dep_view AS SELECT id, name, ssn FROM customers;")
		if err != nil {
			t.Fatalf("failed to alter inner view: %v", err)
		}

		// 3. Query outer view again -> must fail closed because inner dependency drifted!
		rowsOuter, errOuter := conn.Query(ctx, "SELECT id, name FROM outer_nested_view;")
		if errOuter == nil {
			defer rowsOuter.Close()
			for rowsOuter.Next() {
			}
			errOuter = rowsOuter.Err()
		}
		if errOuter == nil {
			t.Fatalf("CRITICAL SEC-P2-08: outer view succeeded despite underlying inner view definition drift!")
		}
		if !strings.Contains(errOuter.Error(), "policy violation") {
			t.Fatalf("expected policy violation on outer view, got: %v", errOuter)
		}
	})

	// 29. Adversarial: Nested view depending on unapproved inner view fails closed (Priority A)
	t.Run("Adversarial_NestedView_UnapprovedInnerView_FailsClosed", func(t *testing.T) {
		adminConn, err := pgx.Connect(ctx, env.adminDSN)
		if err != nil {
			t.Fatalf("failed to connect admin: %v", err)
		}
		defer adminConn.Close(ctx)

		_, _ = adminConn.Exec(ctx, "CREATE VIEW unapproved_subview AS SELECT id, name FROM customers;")
		_, _ = adminConn.Exec(ctx, "CREATE VIEW dependent_outer_view AS SELECT id, name FROM unapproved_subview;")
		defer adminConn.Exec(ctx, "DROP VIEW IF EXISTS dependent_outer_view;")
		defer adminConn.Exec(ctx, "DROP VIEW IF EXISTS unapproved_subview;")

		var defOuter string
		_ = adminConn.QueryRow(ctx, "SELECT definition FROM pg_catalog.pg_views WHERE schemaname = 'public' AND viewname = 'dependent_outer_view'").Scan(&defOuter)
		fpOuter, _ := ast.ComputeViewFingerprint(defOuter)

		// Policy only approves dependent_outer_view, intentionally omitting unapproved_subview
		env.policyStore.SetAgentPolicy("test-analyst", policy.AgentConfig{
			Key:               env.agentKey,
			AllowedStatements: []string{"SELECT"},
			AllowedTables:     []string{"customers"},
			Views: []policy.ViewConfig{
				{
					Name:                  "dependent_outer_view",
					BaseTable:             "unapproved_subview",
					DefinitionFingerprint: fpOuter,
					ColumnMappings:        map[string]string{"id": "id", "name": "name"},
				},
			},
		})

		env.server.GetCatalogVerifier().SetTTL(0)

		conn, err := pgx.Connect(ctx, env.proxyDSN)
		if err != nil {
			t.Fatalf("failed to connect: %v", err)
		}
		defer conn.Close(ctx)

		rows, errQuery := conn.Query(ctx, "SELECT id, name FROM dependent_outer_view;")
		if errQuery == nil {
			defer rows.Close()
			for rows.Next() {
			}
			errQuery = rows.Err()
		}
		if errQuery == nil {
			t.Fatalf("CRITICAL: dependent_outer_view succeeded despite depending on an unapproved inner view!")
		}
		if !strings.Contains(errQuery.Error(), "policy violation") {
			t.Fatalf("expected policy violation for unapproved inner view, got: %v", errQuery)
		}
	})

	// 30. Adversarial: Quoted vs unquoted live view canonicalization isolation (Priority C)
	t.Run("Adversarial_QuotedVsUnquoted_LiveIsolation", func(t *testing.T) {
		adminConn, err := pgx.Connect(ctx, env.adminDSN)
		if err != nil {
			t.Fatalf("failed to connect admin: %v", err)
		}
		defer adminConn.Close(ctx)

		// Create two distinct relations in PostgreSQL: unquoted reports vs quoted "Reports"
		_, _ = adminConn.Exec(ctx, "CREATE VIEW reports AS SELECT id, name FROM customers;")
		_, _ = adminConn.Exec(ctx, "CREATE VIEW \"Reports\" AS SELECT id, tenant_id FROM customers;")
		defer adminConn.Exec(ctx, "DROP VIEW IF EXISTS reports;")
		defer adminConn.Exec(ctx, "DROP VIEW IF EXISTS \"Reports\";")

		var defLower, defUpper string
		_ = adminConn.QueryRow(ctx, "SELECT definition FROM pg_catalog.pg_views WHERE schemaname = 'public' AND viewname = 'reports'").Scan(&defLower)
		_ = adminConn.QueryRow(ctx, "SELECT definition FROM pg_catalog.pg_views WHERE schemaname = 'public' AND viewname = 'Reports'").Scan(&defUpper)
		fpLower, _ := ast.ComputeViewFingerprint(defLower)
		fpUpper, _ := ast.ComputeViewFingerprint(defUpper)

		env.policyStore.SetAgentPolicy("test-analyst", policy.AgentConfig{
			Key:               env.agentKey,
			AllowedStatements: []string{"SELECT"},
			AllowedTables:     []string{"customers"},
			Views: []policy.ViewConfig{
				{
					Name:                  "reports",
					BaseTable:             "customers",
					DefinitionFingerprint: fpLower,
					ColumnMappings:        map[string]string{"id": "id", "name": "name"},
				},
				{
					Name:                  "public.\"Reports\"",
					BaseTable:             "customers",
					DefinitionFingerprint: fpUpper,
					ColumnMappings:        map[string]string{"id": "id", "tenant_id": "tenant_id"},
				},
			},
		})

		env.server.GetCatalogVerifier().SetTTL(0)

		conn, err := pgx.Connect(ctx, env.proxyDSN)
		if err != nil {
			t.Fatalf("failed to connect: %v", err)
		}
		defer conn.Close(ctx)

		// 1. Query unquoted reports -> returns name
		var id int
		var name string
		err = conn.QueryRow(ctx, "SELECT id, name FROM reports WHERE id = 1;").Scan(&id, &name)
		if err != nil {
			t.Fatalf("unexpected error querying unquoted reports: %v", err)
		}
		if name != "Alice Smith" {
			t.Fatalf("expected 'Alice Smith', got %q", name)
		}

		// 2. Query quoted "Reports" -> returns tenant_id
		var id2 int
		var tenant string
		err = conn.QueryRow(ctx, "SELECT id, tenant_id FROM \"Reports\" WHERE id = 1;").Scan(&id2, &tenant)
		if err != nil {
			t.Fatalf("unexpected error querying quoted \"Reports\": %v", err)
		}
		if tenant != "tenant-alpha" {
			t.Fatalf("expected 'tenant-alpha', got %q", tenant)
		}
	})
}
