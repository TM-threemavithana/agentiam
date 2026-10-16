package proxy

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tm-threemavithana/agentiam/internal/ast"
	"github.com/tm-threemavithana/agentiam/internal/policy"
)

type VerifiedViewStatus string

const (
	StatusVerified      VerifiedViewStatus = "verified"
	StatusUnverified    VerifiedViewStatus = "unverified"
	StatusMissing       VerifiedViewStatus = "missing_fingerprint"
	StatusMismatched    VerifiedViewStatus = "fingerprint_mismatch"
	StatusDriftDetected VerifiedViewStatus = "drift_detected"
	StatusError         VerifiedViewStatus = "error"
)

// CatalogSnapshot stores the retrieved definition SQL and fingerprint of a database view
// as read from the PostgreSQL system catalog at a specific point in time.
type CatalogSnapshot struct {
	CanonicalSchema string
	CanonicalName   string
	DefinitionSQL   string
	Fingerprint     string
	FetchedAt       time.Time
}

// ClientViewAuthorization represents the authorization decision for a specific client, policy version, and view.
type ClientViewAuthorization struct {
	ClientID            string
	PolicyVersion       int
	CanonicalSchema     string
	CanonicalName       string
	ExpectedFingerprint string
	ActualFingerprint   string
	Status              VerifiedViewStatus
	Dependencies        []string // canonical keys of dependent views
	VerifiedAt          time.Time
	LastError           error
}

// CatalogReader abstracts querying the PostgreSQL catalog for view definitions and relation types.
// Default implementation is PostgresCatalogReader.
type CatalogReader interface {
	QueryViewDefinition(ctx context.Context, schema, viewName string) (string, error)
	QueryRelationKind(ctx context.Context, schema, relName string) (rune, error)
}

// PostgresCatalogReader connects directly to the PostgreSQL upstream database to query system catalogs.
type PostgresCatalogReader struct {
	upstreamDSN string
}

func NewPostgresCatalogReader(upstreamDSN string) *PostgresCatalogReader {
	return &PostgresCatalogReader{upstreamDSN: upstreamDSN}
}

func (r *PostgresCatalogReader) QueryViewDefinition(ctx context.Context, schema, viewName string) (string, error) {
	conn, err := pgconn.Connect(ctx, r.upstreamDSN)
	if err != nil {
		return "", fmt.Errorf("failed to connect to upstream PostgreSQL catalog: %w", err)
	}
	defer conn.Close(ctx)

	// Query pg_catalog.pg_views directly, ensuring canonical schema and name matching,
	// and assert that relkind is 'v' (view), avoiding relation shadowing attacks.
	sql := `
		SELECT v.definition
		FROM pg_catalog.pg_views v
		JOIN pg_catalog.pg_class c ON c.relname = v.viewname
		JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace AND n.nspname = v.schemaname
		WHERE v.schemaname = $1 AND v.viewname = $2 AND c.relkind = 'v';
	`
	result := conn.ExecParams(ctx, sql, [][]byte{[]byte(schema), []byte(viewName)}, nil, nil, nil)
	defer result.Close()

	var def string
	for result.NextRow() {
		row := result.Values()
		if len(row) > 0 && row[0] != nil {
			def = string(row[0])
		}
	}
	if _, closeErr := result.Close(); closeErr != nil {
		return "", fmt.Errorf("catalog query failed for view '%s.%s': %w", schema, viewName, closeErr)
	}
	if strings.TrimSpace(def) == "" {
		return "", fmt.Errorf("view '%s.%s' does not exist in PostgreSQL catalog or is not a view (fail-closed)", schema, viewName)
	}
	return def, nil
}

func (r *PostgresCatalogReader) QueryRelationKind(ctx context.Context, schema, relName string) (rune, error) {
	conn, err := pgconn.Connect(ctx, r.upstreamDSN)
	if err != nil {
		return 0, fmt.Errorf("failed to connect to upstream PostgreSQL catalog: %w", err)
	}
	defer conn.Close(ctx)

	sql := `
		SELECT c.relkind
		FROM pg_catalog.pg_class c
		JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1 AND c.relname = $2;
	`
	result := conn.ExecParams(ctx, sql, [][]byte{[]byte(schema), []byte(relName)}, nil, nil, nil)
	defer result.Close()

	var kind rune
	for result.NextRow() {
		row := result.Values()
		if len(row) > 0 && len(row[0]) > 0 {
			kind = rune(row[0][0])
		}
	}
	if _, closeErr := result.Close(); closeErr != nil {
		return 0, fmt.Errorf("catalog query failed for relation kind '%s.%s': %w", schema, relName, closeErr)
	}
	if kind == 0 {
		return 0, fmt.Errorf("relation '%s.%s' does not exist in PostgreSQL catalog (fail-closed)", schema, relName)
	}
	return kind, nil
}

// CatalogVerifier validates database view definitions and provenance against live PostgreSQL catalogs,
// enforcing cross-client isolation (SEC-P2-06), runtime drift detection (RISK-VIEW-01), and nested dependency tracking (SEC-P2-08).
type CatalogVerifier struct {
	reader          CatalogReader
	logger          *Logger
	ttl             time.Duration
	mu              sync.RWMutex
	catalogCache    map[string]*CatalogSnapshot         // key: CanonicalViewKey(schema, viewName)
	clientAuthCache map[string]*ClientViewAuthorization // key: clientAuthKey(clientID, version, schema, viewName)
	dependencies    map[string][]string                 // key: CanonicalViewKey -> []CanonicalViewKey
	catalogGens     map[string]uint64                   // key: CanonicalViewKey -> generation counter
	clientGens      map[string]uint64                   // key: clientAuthKey -> generation counter

	// Deterministic synchronization test hooks for out-of-order race testing
	beforeSnapshotWriteHook func(schema, viewName string)
	beforeAuthWriteHook     func(clientID string, schema, viewName string)
}

func NewCatalogVerifier(upstreamDSN string, logger *Logger) *CatalogVerifier {
	return NewCatalogVerifierWithReader(NewPostgresCatalogReader(upstreamDSN), logger)
}

func NewCatalogVerifierWithReader(reader CatalogReader, logger *Logger) *CatalogVerifier {
	return &CatalogVerifier{
		reader:          reader,
		logger:          logger,
		ttl:             50 * time.Millisecond,
		catalogCache:    make(map[string]*CatalogSnapshot),
		clientAuthCache: make(map[string]*ClientViewAuthorization),
		dependencies:    make(map[string][]string),
		catalogGens:     make(map[string]uint64),
		clientGens:      make(map[string]uint64),
	}
}

func (cv *CatalogVerifier) SetTTL(d time.Duration) {
	cv.mu.Lock()
	defer cv.mu.Unlock()
	cv.ttl = d
}

func (cv *CatalogVerifier) GetTTL() time.Duration {
	cv.mu.RLock()
	defer cv.mu.RUnlock()
	return cv.ttl
}

func (cv *CatalogVerifier) SetBeforeSnapshotWriteHook(hook func(schema, viewName string)) {
	cv.mu.Lock()
	defer cv.mu.Unlock()
	cv.beforeSnapshotWriteHook = hook
}

func (cv *CatalogVerifier) SetBeforeAuthWriteHook(hook func(clientID, schema, viewName string)) {
	cv.mu.Lock()
	defer cv.mu.Unlock()
	cv.beforeAuthWriteHook = hook
}

// CanonicalizeIdentifier returns the PostgreSQL canonical representation of an identifier:
// - If the identifier is enclosed in double quotes (e.g. `"Reports"`), quotes are removed and exact case is preserved (`Reports`).
// - If the identifier is unquoted (e.g. `Reports` or `reports`), it is folded to lowercase (`reports`).
func CanonicalizeIdentifier(ident string) string {
	ident = strings.TrimSpace(ident)
	if len(ident) >= 2 && ident[0] == '"' && ident[len(ident)-1] == '"' {
		return ident[1 : len(ident)-1]
	}
	return strings.ToLower(ident)
}

// splitQualifiedIdentifier splits a relation name by unquoted dots, respecting double-quoted identifiers.
func splitQualifiedIdentifier(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var parts []string
	inQuotes := false
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '"' {
			inQuotes = !inQuotes
		} else if s[i] == '.' && !inQuotes {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

func CanonicalViewKey(schema, viewName string) string {
	s := CanonicalizeIdentifier(schema)
	if s == "" {
		s = "public"
	}
	v := CanonicalizeIdentifier(viewName)
	return s + "." + v
}

func SplitSchemaView(name string) (string, string) {
	parts := splitQualifiedIdentifier(name)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "public", name
}

func clientAuthKey(clientID string, version int, schema, viewName string) string {
	cID := strings.TrimSpace(clientID)
	if cID == "" {
		cID = "default"
	}
	return fmt.Sprintf("%s:%d:%s", cID, version, CanonicalViewKey(schema, viewName))
}

// QueryCatalogSnapshot retrieves the canonical view definition and SHA-256 fingerprint from PostgreSQL catalogs,
// caching the snapshot according to the configured TTL and concurrency generation rules.
func (cv *CatalogVerifier) QueryCatalogSnapshot(ctx context.Context, schema, viewName string, force bool) (*CatalogSnapshot, error) {
	key := CanonicalViewKey(schema, viewName)
	dotIdx := strings.Index(key, ".")
	cSchema := key[:dotIdx]
	cName := key[dotIdx+1:]

	cv.mu.RLock()
	startGen := cv.catalogGens[key]
	startTime := time.Now()
	if !force {
		snap, exists := cv.catalogCache[key]
		ttl := cv.ttl
		if exists && snap != nil && (ttl > 0 && time.Since(snap.FetchedAt) < ttl) {
			cv.mu.RUnlock()
			return snap, nil
		}
	}
	cv.mu.RUnlock()

	defSQL, err := cv.reader.QueryViewDefinition(ctx, cSchema, cName)
	if err != nil {
		return nil, err
	}

	fp, err := ast.ComputeViewFingerprint(defSQL)
	if err != nil {
		return nil, fmt.Errorf("failed to compute fingerprint for view '%s': %w", key, err)
	}

	if cv.beforeSnapshotWriteHook != nil {
		cv.beforeSnapshotWriteHook(cSchema, cName)
	}

	cv.mu.Lock()
	defer cv.mu.Unlock()

	currentGen := cv.catalogGens[key]
	// Concurrency guard (Priority B): Only write snapshot if no invalidation occurred in-flight
	// and no newer snapshot was already written.
	if currentGen == startGen {
		existing, exists := cv.catalogCache[key]
		if !exists || !existing.FetchedAt.After(startTime) {
			cv.catalogCache[key] = &CatalogSnapshot{
				CanonicalSchema: cSchema,
				CanonicalName:   cName,
				DefinitionSQL:   defSQL,
				Fingerprint:     fp,
				FetchedAt:       time.Now(),
			}
		}
	}

	snap, exists := cv.catalogCache[key]
	if !exists {
		// Invalidation occurred while in-flight; return ephemeral snapshot but do not cache
		return &CatalogSnapshot{
			CanonicalSchema: cSchema,
			CanonicalName:   cName,
			DefinitionSQL:   defSQL,
			Fingerprint:     fp,
			FetchedAt:       time.Now(),
		}, nil
	}
	return snap, nil
}

// VerifyClientView validates a single view policy for a specific client against the PostgreSQL catalog,
// verifying the client's expected fingerprint, AST provenance (SEC-P2-05, SEC-P2-07), and nested view dependencies (SEC-P2-08).
func (cv *CatalogVerifier) VerifyClientView(
	ctx context.Context,
	clientID string,
	version int,
	vp ast.ViewPolicy,
	maskedColumns map[string][]string,
	viewPolicyMap map[string]ast.ViewPolicy,
	visited map[string]bool,
	forceRefresh bool,
) (*ClientViewAuthorization, error) {
	schema, viewName := SplitSchemaView(vp.Name)
	canonKey := CanonicalViewKey(schema, viewName)
	expectedFP := strings.TrimSpace(vp.DefinitionFingerprint)
	authKey := clientAuthKey(clientID, version, schema, viewName)

	cv.mu.RLock()
	startCatGen := cv.catalogGens[canonKey]
	startClientGen := cv.clientGens[authKey]
	startTime := time.Now()
	cv.mu.RUnlock()

	// Cycle detection for nested views
	if visited == nil {
		visited = make(map[string]bool)
	}
	if visited[canonKey] {
		err := fmt.Errorf("circular dependency detected in view '%s' (fail-closed)", canonKey)
		cv.recordClientStatus(clientID, version, schema, viewName, expectedFP, "", StatusError, nil, err, startCatGen, startClientGen, startTime)
		return nil, err
	}
	visited[canonKey] = true
	defer delete(visited, canonKey)

	if len(visited) > 5 {
		err := fmt.Errorf("view '%s' exceeds maximum nested dependency depth of 5 (fail-closed)", canonKey)
		cv.recordClientStatus(clientID, version, schema, viewName, expectedFP, "", StatusError, nil, err, startCatGen, startClientGen, startTime)
		return nil, err
	}

	// 1. Missing fingerprint check (fail closed)
	if expectedFP == "" {
		err := fmt.Errorf("missing definition fingerprint for approved view '%s' for client '%s' (fail-closed)", canonKey, clientID)
		cv.recordClientStatus(clientID, version, schema, viewName, expectedFP, "", StatusMissing, nil, err, startCatGen, startClientGen, startTime)
		return nil, err
	}

	// 2. Query live PostgreSQL catalog
	snap, err := cv.QueryCatalogSnapshot(ctx, schema, viewName, forceRefresh)
	if err != nil {
		cv.recordClientStatus(clientID, version, schema, viewName, expectedFP, "", StatusError, nil, err, startCatGen, startClientGen, startTime)
		return nil, err
	}

	// 3. Compare fingerprint with client's approved fingerprint (constant-time, case-insensitive)
	if !ast.CompareFingerprints(expectedFP, snap.Fingerprint) {
		err := fmt.Errorf("view definition fingerprint mismatch for '%s': expected %s, got %s (fail-closed)", canonKey, expectedFP, snap.Fingerprint)
		cv.recordClientStatus(clientID, version, schema, viewName, expectedFP, snap.Fingerprint, StatusMismatched, nil, err, startCatGen, startClientGen, startTime)
		return nil, err
	}

	// 4. Deep AST provenance analysis (SEC-P2-05 computed column check & SEC-P2-07 sensitive predicate check)
	if err := ast.ValidateViewProvenance(snap.DefinitionSQL, vp, maskedColumns); err != nil {
		cv.recordClientStatus(clientID, version, schema, viewName, expectedFP, snap.Fingerprint, StatusError, nil, err, startCatGen, startClientGen, startTime)
		return nil, fmt.Errorf("view '%s' provenance validation failed: %w (fail-closed)", canonKey, err)
	}

	// 5. Recursively validate nested view dependencies (SEC-P2-08 & Priority A fail-closed)
	var directDependencies []string
	rawDeps, depErr := ast.ExtractViewDependencies(snap.DefinitionSQL)
	if depErr != nil {
		err := fmt.Errorf("failed to extract view dependencies for '%s': %w (fail-closed)", canonKey, depErr)
		cv.recordClientStatus(clientID, version, schema, viewName, expectedFP, snap.Fingerprint, StatusError, nil, err, startCatGen, startClientGen, startTime)
		return nil, err
	}

	for _, dep := range rawDeps {
		depSchema, depName := SplitSchemaView(dep)
		depCanon := CanonicalViewKey(depSchema, depName)
		depBare := CanonicalizeIdentifier(depName)
		dotIdx := strings.Index(depCanon, ".")
		depCSchema := depCanon[:dotIdx]
		depCName := depCanon[dotIdx+1:]

		relKind, err := cv.reader.QueryRelationKind(ctx, depCSchema, depCName)
		if err != nil {
			errClosed := fmt.Errorf("view '%s' dependency '%s' catalog lookup failed: %w (fail-closed)", canonKey, depCanon, err)
			cv.recordClientStatus(clientID, version, schema, viewName, expectedFP, snap.Fingerprint, StatusError, directDependencies, errClosed, startCatGen, startClientGen, startTime)
			return nil, errClosed
		}

		switch relKind {
		case 'v': // PostgreSQL View
			var parentVP ast.ViewPolicy
			var isApproved bool
			if p, ok := viewPolicyMap[depCanon]; ok {
				parentVP = p
				isApproved = true
			} else if p, ok := viewPolicyMap[depBare]; ok {
				parentVP = p
				isApproved = true
			}

			if !isApproved {
				unapprovedErr := fmt.Errorf("view '%s' depends on unapproved view '%s' (fail-closed)", canonKey, depCanon)
				cv.recordClientStatus(clientID, version, schema, viewName, expectedFP, snap.Fingerprint, StatusError, directDependencies, unapprovedErr, startCatGen, startClientGen, startTime)
				return nil, unapprovedErr
			}

			directDependencies = append(directDependencies, depCanon)
			if _, err := cv.VerifyClientView(ctx, clientID, version, parentVP, maskedColumns, viewPolicyMap, visited, forceRefresh); err != nil {
				nestedErr := fmt.Errorf("view '%s' underlying dependency '%s' verification failed: %w", canonKey, depCanon, err)
				cv.recordClientStatus(clientID, version, schema, viewName, expectedFP, snap.Fingerprint, StatusError, directDependencies, nestedErr, startCatGen, startClientGen, startTime)
				return nil, nestedErr
			}

		case 'r', 'p': // Ordinary base table ('r') or partitioned table ('p')
			continue

		default: // Unsupported relation type: 'm' (materialized view), 'f' (foreign table), etc.
			unsupportedErr := fmt.Errorf("view '%s' depends on unsupported relation '%s' of type '%c' (fail-closed)", canonKey, depCanon, relKind)
			cv.recordClientStatus(clientID, version, schema, viewName, expectedFP, snap.Fingerprint, StatusError, directDependencies, unsupportedErr, startCatGen, startClientGen, startTime)
			return nil, unsupportedErr
		}
	}

	cv.mu.Lock()
	cv.dependencies[canonKey] = directDependencies
	cv.mu.Unlock()

	auth := cv.recordClientStatus(clientID, version, schema, viewName, expectedFP, snap.Fingerprint, StatusVerified, directDependencies, nil, startCatGen, startClientGen, startTime)
	return auth, nil
}

func (cv *CatalogVerifier) recordClientStatus(
	clientID string,
	version int,
	schema, viewName, expectedFP, actualFP string,
	status VerifiedViewStatus,
	dependencies []string,
	err error,
	startCatGen uint64,
	startClientGen uint64,
	startTime time.Time,
) *ClientViewAuthorization {
	canonKey := CanonicalViewKey(schema, viewName)
	dotIdx := strings.Index(canonKey, ".")
	cSchema := canonKey[:dotIdx]
	cName := canonKey[dotIdx+1:]
	authKey := clientAuthKey(clientID, version, schema, viewName)

	if cv.beforeAuthWriteHook != nil {
		cv.beforeAuthWriteHook(clientID, cSchema, cName)
	}

	cv.mu.Lock()
	defer cv.mu.Unlock()

	currentCatGen := cv.catalogGens[canonKey]
	currentClientGen := cv.clientGens[authKey]

	// Concurrency guard (Priority B):
	// 1. If an invalidation occurred while in-flight (generation changed),
	// an older in-flight check MUST NOT record StatusVerified.
	if (currentCatGen != startCatGen || currentClientGen != startClientGen) && status == StatusVerified {
		return &ClientViewAuthorization{
			ClientID:            clientID,
			PolicyVersion:       version,
			CanonicalSchema:     cSchema,
			CanonicalName:       cName,
			ExpectedFingerprint: expectedFP,
			ActualFingerprint:   actualFP,
			Status:              StatusUnverified,
			Dependencies:        dependencies,
			VerifiedAt:          time.Now(),
			LastError:           fmt.Errorf("view authorization invalidated in-flight"),
		}
	}

	// 2. If a newer authorization was already written after this verification started:
	existing, ok := cv.clientAuthCache[authKey]
	if ok && existing != nil && existing.VerifiedAt.After(startTime) {
		// A newer check already completed. If the newer check failed (error/mismatch),
		// an older in-flight StatusVerified MUST NOT overwrite the newer failure!
		if status == StatusVerified && existing.Status != StatusVerified {
			return existing
		}
	}

	auth := &ClientViewAuthorization{
		ClientID:            clientID,
		PolicyVersion:       version,
		CanonicalSchema:     cSchema,
		CanonicalName:       cName,
		ExpectedFingerprint: expectedFP,
		ActualFingerprint:   actualFP,
		Status:              status,
		Dependencies:        dependencies,
		VerifiedAt:          time.Now(),
		LastError:           err,
	}

	cv.clientAuthCache[authKey] = auth
	return auth
}

// VerifyClientRules validates all views defined in an ast.Rules struct for a specific client.
func (cv *CatalogVerifier) VerifyClientRules(ctx context.Context, clientID string, version int, rules *ast.Rules) error {
	if len(rules.Views) == 0 {
		return nil
	}

	viewPolicyMap := make(map[string]ast.ViewPolicy)
	for _, v := range rules.Views {
		schema, name := SplitSchemaView(v.Name)
		viewPolicyMap[CanonicalViewKey(schema, name)] = v
		viewPolicyMap[CanonicalizeIdentifier(name)] = v
	}

	if rules.VerifiedViews == nil {
		rules.VerifiedViews = make(map[string]bool)
	}
	rules.RequireCatalogVerification = true

	var firstErr error
	for _, v := range rules.Views {
		schema, name := SplitSchemaView(v.Name)
		key := CanonicalViewKey(schema, name)
		bareKey := CanonicalizeIdentifier(name)

		_, err := cv.VerifyClientView(ctx, clientID, version, v, rules.MaskedColumns, viewPolicyMap, nil, true)
		if err != nil {
			rules.VerifiedViews[key] = false
			rules.VerifiedViews[bareKey] = false
			if firstErr == nil {
				firstErr = err
			}
		} else {
			rules.VerifiedViews[key] = true
			rules.VerifiedViews[bareKey] = true
		}
	}

	return firstErr
}

// EnsureFreshness checks whether any views referenced in the query need catalog re-verification (RISK-VIEW-01),
// re-evaluating definition freshness and fail-closing if drift or mismatch is detected.
func (cv *CatalogVerifier) EnsureFreshness(
	ctx context.Context,
	clientID string,
	version int,
	rules *ast.Rules,
	referencedRelations []string,
) error {
	if len(rules.Views) == 0 || len(referencedRelations) == 0 {
		return nil
	}

	viewPolicyMap := make(map[string]ast.ViewPolicy)
	for _, v := range rules.Views {
		schema, name := SplitSchemaView(v.Name)
		viewPolicyMap[CanonicalViewKey(schema, name)] = v
		viewPolicyMap[CanonicalizeIdentifier(name)] = v
	}

	for _, rel := range referencedRelations {
		schema, name := SplitSchemaView(rel)
		canonKey := CanonicalViewKey(schema, name)
		bareKey := CanonicalizeIdentifier(name)

		vp, isConfigured := viewPolicyMap[canonKey]
		if !isConfigured {
			vp, isConfigured = viewPolicyMap[bareKey]
		}
		if !isConfigured {
			continue // Relation is not a view configured in policy
		}

		authKey := clientAuthKey(clientID, version, schema, name)
		cv.mu.RLock()
		auth, authExists := cv.clientAuthCache[authKey]
		ttl := cv.ttl
		cv.mu.RUnlock()

		needsCheck := !authExists || auth == nil || (ttl == 0 || time.Since(auth.VerifiedAt) >= ttl)
		if needsCheck {
			// Query fresh catalog definition and re-verify
			newAuth, err := cv.VerifyClientView(ctx, clientID, version, vp, rules.MaskedColumns, viewPolicyMap, nil, true)
			if err != nil {
				return fmt.Errorf("policy violation: view '%s' verification failed during runtime freshness check: %w", canonKey, err)
			}
			if newAuth.Status != StatusVerified {
				return fmt.Errorf("policy violation: view '%s' has unverified status '%s' (fail-closed)", canonKey, newAuth.Status)
			}
		} else {
			if auth.Status != StatusVerified {
				return fmt.Errorf("policy violation: view '%s' is not verified for client '%s' (fail-closed)", canonKey, clientID)
			}
			// Check freshness of recorded dependencies (SEC-P2-08)
			for _, depCanon := range auth.Dependencies {
				depVP, hasDepVP := viewPolicyMap[depCanon]
				if hasDepVP {
					if _, err := cv.VerifyClientView(ctx, clientID, version, depVP, rules.MaskedColumns, viewPolicyMap, nil, false); err != nil {
						return fmt.Errorf("policy violation: underlying dependency '%s' of view '%s' failed verification: %w", depCanon, canonKey, err)
					}
				} else {
					return fmt.Errorf("policy violation: underlying dependency '%s' of view '%s' is not approved in policy (fail-closed)", depCanon, canonKey)
				}
			}
		}
	}

	return nil
}

// EnrichRulesWithVerifiedViews returns an isolated, immutable copy of Rules populated with verified view decisions
// scoped strictly to the given clientID and policy version (SEC-P2-06).
func (cv *CatalogVerifier) EnrichRulesWithVerifiedViews(clientID string, version int, rules ast.Rules) ast.Rules {
	cv.mu.RLock()
	defer cv.mu.RUnlock()

	newRules := rules
	newRules.RequireCatalogVerification = true
	newRules.VerifiedViews = make(map[string]bool)

	for _, v := range rules.Views {
		schema, name := SplitSchemaView(v.Name)
		key := CanonicalViewKey(schema, name)
		bareKey := CanonicalizeIdentifier(name)
		authKey := clientAuthKey(clientID, version, schema, name)

		auth, exists := cv.clientAuthCache[authKey]
		if exists && auth != nil && auth.Status == StatusVerified {
			if ast.CompareFingerprints(v.DefinitionFingerprint, auth.ActualFingerprint) {
				newRules.VerifiedViews[key] = true
				newRules.VerifiedViews[bareKey] = true
				continue
			}
		}
		newRules.VerifiedViews[key] = false
		newRules.VerifiedViews[bareKey] = false
	}

	return newRules
}

// CheckDrift checks whether the live PostgreSQL catalog definition of a view has drifted from its cached snapshot.
func (cv *CatalogVerifier) CheckDrift(ctx context.Context, schema, viewName string) (bool, error) {
	key := CanonicalViewKey(schema, viewName)
	dotIdx := strings.Index(key, ".")
	cSchema := key[:dotIdx]
	cName := key[dotIdx+1:]

	cv.mu.RLock()
	snap, exists := cv.catalogCache[key]
	cv.mu.RUnlock()

	currentDef, err := cv.reader.QueryViewDefinition(ctx, cSchema, cName)
	if err != nil {
		return true, fmt.Errorf("catalog query failed for view '%s': %w", key, err)
	}

	currentFP, err := ast.ComputeViewFingerprint(currentDef)
	if err != nil {
		return true, fmt.Errorf("failed to compute fingerprint for view '%s': %w", key, err)
	}

	if exists && snap != nil {
		if !ast.CompareFingerprints(snap.Fingerprint, currentFP) {
			return true, fmt.Errorf("schema drift detected: view '%s' fingerprint changed from %s to %s", key, snap.Fingerprint, currentFP)
		}
	}

	return false, nil
}

// CheckClientDrift checks whether the view has drifted relative to the client's approved fingerprint.
func (cv *CatalogVerifier) CheckClientDrift(ctx context.Context, clientID string, version int, schema, viewName string) (bool, error) {
	key := CanonicalViewKey(schema, viewName)
	dotIdx := strings.Index(key, ".")
	cSchema := key[:dotIdx]
	cName := key[dotIdx+1:]
	authKey := clientAuthKey(clientID, version, schema, viewName)

	cv.mu.RLock()
	auth, exists := cv.clientAuthCache[authKey]
	cv.mu.RUnlock()

	if !exists || auth == nil || auth.Status != StatusVerified {
		return true, fmt.Errorf("view '%s' is not in verified state for client '%s'", key, clientID)
	}

	currentDef, err := cv.reader.QueryViewDefinition(ctx, cSchema, cName)
	if err != nil {
		return true, err
	}

	currentFP, err := ast.ComputeViewFingerprint(currentDef)
	if err != nil {
		return true, err
	}

	if !ast.CompareFingerprints(auth.ExpectedFingerprint, currentFP) {
		err := fmt.Errorf("schema drift detected: view '%s' fingerprint changed from %s to %s", key, auth.ExpectedFingerprint, currentFP)
		cv.recordClientStatus(clientID, version, schema, viewName, auth.ExpectedFingerprint, currentFP, StatusDriftDetected, auth.Dependencies, err, 0, 0, time.Time{})
		return true, err
	}

	return false, nil
}

// InvalidateView purges cached catalog and client authorizations for a specific view.
func (cv *CatalogVerifier) InvalidateView(schema, viewName string) {
	key := CanonicalViewKey(schema, viewName)
	dotIdx := strings.Index(key, ".")
	cSchema := key[:dotIdx]
	cName := key[dotIdx+1:]

	cv.mu.Lock()
	defer cv.mu.Unlock()

	cv.catalogGens[key]++
	delete(cv.catalogCache, key)

	for authKey, auth := range cv.clientAuthCache {
		if auth.CanonicalSchema == cSchema && auth.CanonicalName == cName {
			cv.clientGens[authKey]++
			auth.Status = StatusUnverified
			auth.LastError = fmt.Errorf("view explicitly invalidated")
			delete(cv.clientAuthCache, authKey)
		}
	}
}

// InvalidateAll clears all cached catalog snapshots and client authorizations.
func (cv *CatalogVerifier) InvalidateAll() {
	cv.mu.Lock()
	defer cv.mu.Unlock()

	for k := range cv.catalogGens {
		cv.catalogGens[k]++
	}
	for k := range cv.clientGens {
		cv.clientGens[k]++
	}
	cv.catalogCache = make(map[string]*CatalogSnapshot)
	cv.clientAuthCache = make(map[string]*ClientViewAuthorization)
	cv.dependencies = make(map[string][]string)
}

// IsViewVerified returns whether the view is currently verified for the given client and policy version.
func (cv *CatalogVerifier) IsViewVerified(clientID string, version int, schema, viewName string) bool {
	authKey := clientAuthKey(clientID, version, schema, viewName)
	cv.mu.RLock()
	defer cv.mu.RUnlock()
	auth, ok := cv.clientAuthCache[authKey]
	return ok && auth != nil && auth.Status == StatusVerified
}

// VerifyStore verifies all views across all clients in the policy store against live PostgreSQL catalogs.
func (cv *CatalogVerifier) VerifyStore(ctx context.Context, store *policy.Store) error {
	if store == nil {
		return nil
	}
	versions, err := store.GetAgentVersions()
	if err != nil {
		return err
	}

	var firstErr error
	for agentID := range versions {
		rules, ver := store.GetAgentPolicy(agentID)
		if ver == 0 {
			continue
		}
		if len(rules.Views) > 0 {
			if err := cv.VerifyClientRules(ctx, agentID, ver, &rules); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}
