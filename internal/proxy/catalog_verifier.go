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

type VerifiedViewStatus int

const (
	StatusUnverified VerifiedViewStatus = iota
	StatusVerified
	StatusMismatched
	StatusMissing
	StatusDriftDetected
	StatusError
)

func (s VerifiedViewStatus) String() string {
	switch s {
	case StatusVerified:
		return "verified"
	case StatusMismatched:
		return "mismatched"
	case StatusMissing:
		return "missing_in_catalog"
	case StatusDriftDetected:
		return "drift_detected"
	case StatusError:
		return "error"
	default:
		return "unverified"
	}
}

// CatalogSnapshot represents the raw database catalog state for a PostgreSQL view.
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

// CatalogReader abstracts querying the PostgreSQL catalog for view definitions.
// Default implementation is PostgresCatalogReader.
type CatalogReader interface {
	QueryViewDefinition(ctx context.Context, schema, viewName string) (string, error)
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
	_, closeErr := result.Close()
	if closeErr != nil {
		return "", fmt.Errorf("catalog query failed for view '%s.%s': %w", schema, viewName, closeErr)
	}
	if strings.TrimSpace(def) == "" {
		return "", fmt.Errorf("view '%s.%s' does not exist in PostgreSQL catalog or is not a view (fail-closed)", schema, viewName)
	}
	return def, nil
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
}

func NewCatalogVerifier(upstreamDSN string, logger *Logger) *CatalogVerifier {
	return &CatalogVerifier{
		reader:          NewPostgresCatalogReader(upstreamDSN),
		logger:          logger,
		ttl:             50 * time.Millisecond, // default low TTL for sub-second drift detection
		catalogCache:    make(map[string]*CatalogSnapshot),
		clientAuthCache: make(map[string]*ClientViewAuthorization),
		dependencies:    make(map[string][]string),
	}
}

func NewCatalogVerifierWithReader(reader CatalogReader, logger *Logger) *CatalogVerifier {
	return &CatalogVerifier{
		reader:          reader,
		logger:          logger,
		ttl:             50 * time.Millisecond,
		catalogCache:    make(map[string]*CatalogSnapshot),
		clientAuthCache: make(map[string]*ClientViewAuthorization),
		dependencies:    make(map[string][]string),
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

func CanonicalViewKey(schema, viewName string) string {
	s := strings.ToLower(strings.TrimSpace(schema))
	if s == "" {
		s = "public"
	}
	v := strings.ToLower(strings.TrimSpace(viewName))
	return s + "." + v
}

func SplitSchemaView(name string) (string, string) {
	norm := strings.ToLower(strings.TrimSpace(name))
	parts := strings.Split(norm, ".")
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "public", norm
}

func clientAuthKey(clientID string, version int, schema, viewName string) string {
	cID := strings.ToLower(strings.TrimSpace(clientID))
	if cID == "" {
		cID = "default"
	}
	return fmt.Sprintf("%s:%d:%s", cID, version, CanonicalViewKey(schema, viewName))
}

// QueryCatalogSnapshot retrieves the canonical view definition and SHA-256 fingerprint from PostgreSQL catalogs,
// caching the snapshot according to the configured TTL.
func (cv *CatalogVerifier) QueryCatalogSnapshot(ctx context.Context, schema, viewName string, force bool) (*CatalogSnapshot, error) {
	key := CanonicalViewKey(schema, viewName)

	if !force {
		cv.mu.RLock()
		snap, exists := cv.catalogCache[key]
		ttl := cv.ttl
		cv.mu.RUnlock()
		if exists && snap != nil && (ttl > 0 && time.Since(snap.FetchedAt) < ttl) {
			return snap, nil
		}
	}

	defSQL, err := cv.reader.QueryViewDefinition(ctx, schema, viewName)
	if err != nil {
		return nil, err
	}

	fp, err := ast.ComputeViewFingerprint(defSQL)
	if err != nil {
		return nil, fmt.Errorf("failed to compute fingerprint for view '%s': %w", key, err)
	}

	snap := &CatalogSnapshot{
		CanonicalSchema: schema,
		CanonicalName:   viewName,
		DefinitionSQL:   defSQL,
		Fingerprint:     fp,
		FetchedAt:       time.Now(),
	}

	cv.mu.Lock()
	cv.catalogCache[key] = snap
	cv.mu.Unlock()

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

	// Cycle detection for nested views
	if visited == nil {
		visited = make(map[string]bool)
	}
	if visited[canonKey] {
		err := fmt.Errorf("circular dependency detected in view '%s' (fail-closed)", canonKey)
		cv.recordClientStatus(clientID, version, schema, viewName, expectedFP, "", StatusError, nil, err)
		return nil, err
	}
	visited[canonKey] = true
	defer delete(visited, canonKey)

	if len(visited) > 5 {
		err := fmt.Errorf("view '%s' exceeds maximum nested dependency depth of 5 (fail-closed)", canonKey)
		cv.recordClientStatus(clientID, version, schema, viewName, expectedFP, "", StatusError, nil, err)
		return nil, err
	}

	// 1. Missing fingerprint check (fail closed)
	if expectedFP == "" {
		err := fmt.Errorf("missing definition fingerprint for approved view '%s' for client '%s' (fail-closed)", canonKey, clientID)
		cv.recordClientStatus(clientID, version, schema, viewName, expectedFP, "", StatusMissing, nil, err)
		return nil, err
	}

	// 2. Query live PostgreSQL catalog
	snap, err := cv.QueryCatalogSnapshot(ctx, schema, viewName, forceRefresh)
	if err != nil {
		cv.recordClientStatus(clientID, version, schema, viewName, expectedFP, "", StatusError, nil, err)
		return nil, err
	}

	// 3. Compare fingerprint with client's approved fingerprint (constant-time, case-insensitive)
	if !ast.CompareFingerprints(expectedFP, snap.Fingerprint) {
		err := fmt.Errorf("view definition fingerprint mismatch for '%s': expected %s, got %s (fail-closed)", canonKey, expectedFP, snap.Fingerprint)
		cv.recordClientStatus(clientID, version, schema, viewName, expectedFP, snap.Fingerprint, StatusMismatched, nil, err)
		return nil, err
	}

	// 4. Deep AST provenance analysis (SEC-P2-05 computed column check & SEC-P2-07 sensitive predicate check)
	if err := ast.ValidateViewProvenance(snap.DefinitionSQL, vp, maskedColumns); err != nil {
		cv.recordClientStatus(clientID, version, schema, viewName, expectedFP, snap.Fingerprint, StatusError, nil, err)
		return nil, fmt.Errorf("view '%s' provenance validation failed: %w (fail-closed)", canonKey, err)
	}

	// 5. Recursively validate nested view dependencies (SEC-P2-08)
	var directDependencies []string
	rawDeps, depErr := ast.ExtractViewDependencies(snap.DefinitionSQL)
	if depErr == nil {
		for _, dep := range rawDeps {
			depSchema, depName := SplitSchemaView(dep)
			depCanon := CanonicalViewKey(depSchema, depName)
			depBare := strings.ToLower(depName)

			var parentVP ast.ViewPolicy
			var isNested bool
			if p, ok := viewPolicyMap[depCanon]; ok {
				parentVP = p
				isNested = true
			} else if p, ok := viewPolicyMap[depBare]; ok {
				parentVP = p
				isNested = true
			}

			if isNested {
				directDependencies = append(directDependencies, depCanon)
				if _, err := cv.VerifyClientView(ctx, clientID, version, parentVP, maskedColumns, viewPolicyMap, visited, forceRefresh); err != nil {
					nestedErr := fmt.Errorf("view '%s' underlying dependency '%s' verification failed: %w", canonKey, dep, err)
					cv.recordClientStatus(clientID, version, schema, viewName, expectedFP, snap.Fingerprint, StatusError, directDependencies, nestedErr)
					return nil, nestedErr
				}
			}
		}
	}

	cv.mu.Lock()
	cv.dependencies[canonKey] = directDependencies
	cv.mu.Unlock()

	auth := cv.recordClientStatus(clientID, version, schema, viewName, expectedFP, snap.Fingerprint, StatusVerified, directDependencies, nil)
	return auth, nil
}

func (cv *CatalogVerifier) recordClientStatus(
	clientID string,
	version int,
	schema, viewName, expectedFP, actualFP string,
	status VerifiedViewStatus,
	dependencies []string,
	err error,
) *ClientViewAuthorization {
	key := clientAuthKey(clientID, version, schema, viewName)
	auth := &ClientViewAuthorization{
		ClientID:            clientID,
		PolicyVersion:       version,
		CanonicalSchema:     schema,
		CanonicalName:       viewName,
		ExpectedFingerprint: expectedFP,
		ActualFingerprint:   actualFP,
		Status:              status,
		Dependencies:        dependencies,
		VerifiedAt:          time.Now(),
		LastError:           err,
	}

	cv.mu.Lock()
	cv.clientAuthCache[key] = auth
	cv.mu.Unlock()

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
		viewPolicyMap[strings.ToLower(name)] = v
	}

	if rules.VerifiedViews == nil {
		rules.VerifiedViews = make(map[string]bool)
	}
	rules.RequireCatalogVerification = true

	var firstErr error
	for _, v := range rules.Views {
		schema, name := SplitSchemaView(v.Name)
		key := CanonicalViewKey(schema, name)
		bareKey := strings.ToLower(name)

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
		viewPolicyMap[strings.ToLower(name)] = v
	}

	for _, rel := range referencedRelations {
		schema, name := SplitSchemaView(rel)
		canonKey := CanonicalViewKey(schema, name)
		bareKey := strings.ToLower(name)

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
		bareKey := strings.ToLower(name)
		authKey := clientAuthKey(clientID, version, schema, name)

		auth, exists := cv.clientAuthCache[authKey]
		if exists && auth != nil && auth.Status == StatusVerified {
			// Verify that client's configured fingerprint matches the cached actual fingerprint
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

	cv.mu.RLock()
	snap, exists := cv.catalogCache[key]
	cv.mu.RUnlock()

	currentDef, err := cv.reader.QueryViewDefinition(ctx, schema, viewName)
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
	authKey := clientAuthKey(clientID, version, schema, viewName)

	cv.mu.RLock()
	auth, exists := cv.clientAuthCache[authKey]
	cv.mu.RUnlock()

	if !exists || auth == nil || auth.Status != StatusVerified {
		return true, fmt.Errorf("view '%s' is not in verified state for client '%s'", key, clientID)
	}

	currentDef, err := cv.reader.QueryViewDefinition(ctx, schema, viewName)
	if err != nil {
		return true, err
	}

	currentFP, err := ast.ComputeViewFingerprint(currentDef)
	if err != nil {
		return true, err
	}

	if !ast.CompareFingerprints(auth.ExpectedFingerprint, currentFP) {
		err := fmt.Errorf("schema drift detected: view '%s' fingerprint changed from %s to %s", key, auth.ExpectedFingerprint, currentFP)
		cv.recordClientStatus(clientID, version, schema, viewName, auth.ExpectedFingerprint, currentFP, StatusDriftDetected, auth.Dependencies, err)
		return true, err
	}

	return false, nil
}

// InvalidateView purges cached catalog and client authorizations for a specific view.
func (cv *CatalogVerifier) InvalidateView(schema, viewName string) {
	key := CanonicalViewKey(schema, viewName)

	cv.mu.Lock()
	defer cv.mu.Unlock()

	delete(cv.catalogCache, key)

	for authKey, auth := range cv.clientAuthCache {
		if auth.CanonicalSchema == schema && auth.CanonicalName == viewName {
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
