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

type VerifiedViewInfo struct {
	CanonicalSchema     string
	CanonicalName       string
	ExpectedFingerprint string
	ActualFingerprint   string
	DefinitionSQL       string
	Status              VerifiedViewStatus
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

// CatalogVerifier validates database view definitions and provenance against live PostgreSQL catalogs.
type CatalogVerifier struct {
	reader CatalogReader
	logger *Logger
	mu     sync.RWMutex
	views  map[string]*VerifiedViewInfo // key: "schema.viewname"
}

func NewCatalogVerifier(upstreamDSN string, logger *Logger) *CatalogVerifier {
	return &CatalogVerifier{
		reader: NewPostgresCatalogReader(upstreamDSN),
		logger: logger,
		views:  make(map[string]*VerifiedViewInfo),
	}
}

func NewCatalogVerifierWithReader(reader CatalogReader, logger *Logger) *CatalogVerifier {
	return &CatalogVerifier{
		reader: reader,
		logger: logger,
		views:  make(map[string]*VerifiedViewInfo),
	}
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

func (cv *CatalogVerifier) recordStatus(schema, viewName, expectedFP, actualFP, defSQL string, status VerifiedViewStatus, err error) *VerifiedViewInfo {
	key := CanonicalViewKey(schema, viewName)
	info := &VerifiedViewInfo{
		CanonicalSchema:     schema,
		CanonicalName:       viewName,
		ExpectedFingerprint: expectedFP,
		ActualFingerprint:   actualFP,
		DefinitionSQL:       defSQL,
		Status:              status,
		VerifiedAt:          time.Now(),
		LastError:           err,
	}
	cv.mu.Lock()
	cv.views[key] = info
	cv.mu.Unlock()
	return info
}

// VerifyView verifies a single view policy against the PostgreSQL catalog and AST rules.
func (cv *CatalogVerifier) VerifyView(ctx context.Context, vp ast.ViewPolicy, maskedColumns map[string][]string, viewPolicyMap map[string]ast.ViewPolicy) (*VerifiedViewInfo, error) {
	schema, viewName := SplitSchemaView(vp.Name)
	expectedFP := strings.TrimSpace(vp.DefinitionFingerprint)

	// 1. Missing fingerprint check (fail closed)
	if expectedFP == "" {
		err := fmt.Errorf("missing definition fingerprint for approved view '%s.%s' (fail-closed)", schema, viewName)
		cv.recordStatus(schema, viewName, expectedFP, "", "", StatusMissing, err)
		return nil, err
	}

	// 2. Query live PostgreSQL catalog
	defSQL, err := cv.reader.QueryViewDefinition(ctx, schema, viewName)
	if err != nil {
		cv.recordStatus(schema, viewName, expectedFP, "", "", StatusError, err)
		return nil, err
	}

	// 3. Compute actual fingerprint
	actualFP, err := ast.ComputeViewFingerprint(defSQL)
	if err != nil {
		cv.recordStatus(schema, viewName, expectedFP, "", defSQL, StatusError, err)
		return nil, fmt.Errorf("failed to compute fingerprint for view '%s.%s': %w", schema, viewName, err)
	}

	// 4. Compare fingerprint with owner-approved fingerprint (constant-time, case-insensitive)
	if !ast.CompareFingerprints(expectedFP, actualFP) {
		err := fmt.Errorf("view definition fingerprint mismatch for '%s.%s': expected %s, got %s (fail-closed)", schema, viewName, expectedFP, actualFP)
		cv.recordStatus(schema, viewName, expectedFP, actualFP, defSQL, StatusMismatched, err)
		return nil, err
	}

	// 5. Deep AST provenance analysis (SEC-P2-05)
	if err := ast.ValidateViewProvenance(defSQL, vp, maskedColumns); err != nil {
		cv.recordStatus(schema, viewName, expectedFP, actualFP, defSQL, StatusError, err)
		return nil, fmt.Errorf("view '%s.%s' provenance validation failed: %w (fail-closed)", schema, viewName, err)
	}

	// 6. Recursively validate nested view dependencies
	baseNorm := strings.ToLower(vp.BaseTable)
	bareBase := baseNorm
	if idx := strings.Index(bareBase, "."); idx != -1 {
		bareBase = bareBase[idx+1:]
	}
	if parentVP, isNested := viewPolicyMap[baseNorm]; isNested {
		if _, err := cv.VerifyView(ctx, parentVP, maskedColumns, viewPolicyMap); err != nil {
			err = fmt.Errorf("view '%s.%s' dependency '%s' verification failed: %w", schema, viewName, vp.BaseTable, err)
			cv.recordStatus(schema, viewName, expectedFP, actualFP, defSQL, StatusError, err)
			return nil, err
		}
	} else if parentVP, isNested := viewPolicyMap[bareBase]; isNested {
		if _, err := cv.VerifyView(ctx, parentVP, maskedColumns, viewPolicyMap); err != nil {
			err = fmt.Errorf("view '%s.%s' dependency '%s' verification failed: %w", schema, viewName, vp.BaseTable, err)
			cv.recordStatus(schema, viewName, expectedFP, actualFP, defSQL, StatusError, err)
			return nil, err
		}
	}

	info := cv.recordStatus(schema, viewName, expectedFP, actualFP, defSQL, StatusVerified, nil)
	return info, nil
}

// VerifyRules validates all views defined in an ast.Rules struct against PostgreSQL catalog.
// It populates rules.VerifiedViews and sets rules.RequireCatalogVerification = true.
func (cv *CatalogVerifier) VerifyRules(ctx context.Context, rules *ast.Rules) error {
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

		_, err := cv.VerifyView(ctx, v, rules.MaskedColumns, viewPolicyMap)
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

// CheckDrift re-queries the PostgreSQL catalog for the specified view and checks whether its
// definition has changed since it was verified. Returns true if drift is detected.
func (cv *CatalogVerifier) CheckDrift(ctx context.Context, schema, viewName string) (bool, error) {
	key := CanonicalViewKey(schema, viewName)
	cv.mu.RLock()
	cached, exists := cv.views[key]
	cv.mu.RUnlock()

	if !exists || cached.Status != StatusVerified {
		return true, fmt.Errorf("view '%s' is not in verified state", key)
	}

	currentDef, err := cv.reader.QueryViewDefinition(ctx, cached.CanonicalSchema, cached.CanonicalName)
	if err != nil {
		cv.recordStatus(cached.CanonicalSchema, cached.CanonicalName, cached.ExpectedFingerprint, "", "", StatusError, err)
		return true, err
	}

	currentFP, err := ast.ComputeViewFingerprint(currentDef)
	if err != nil {
		return true, err
	}

	if !ast.CompareFingerprints(cached.ExpectedFingerprint, currentFP) {
		err := fmt.Errorf("schema drift detected: view '%s' fingerprint changed from %s to %s", key, cached.ExpectedFingerprint, currentFP)
		cv.recordStatus(cached.CanonicalSchema, cached.CanonicalName, cached.ExpectedFingerprint, currentFP, currentDef, StatusDriftDetected, err)
		return true, err
	}

	return false, nil
}

// InvalidateView marks a view as unverified in the cache.
func (cv *CatalogVerifier) InvalidateView(schema, viewName string) {
	key := CanonicalViewKey(schema, viewName)
	cv.mu.Lock()
	if v, ok := cv.views[key]; ok {
		v.Status = StatusUnverified
		v.LastError = fmt.Errorf("view explicitly invalidated")
	}
	cv.mu.Unlock()
}

// InvalidateAll clears all cached verified views.
func (cv *CatalogVerifier) InvalidateAll() {
	cv.mu.Lock()
	cv.views = make(map[string]*VerifiedViewInfo)
	cv.mu.Unlock()
}

// IsViewVerified returns whether the view is currently verified.
func (cv *CatalogVerifier) IsViewVerified(schema, viewName string) bool {
	key := CanonicalViewKey(schema, viewName)
	cv.mu.RLock()
	defer cv.mu.RUnlock()
	v, ok := cv.views[key]
	return ok && v.Status == StatusVerified
}

// EnrichRulesWithVerifiedViews creates a copy of rules with current verified view statuses populated.
func (cv *CatalogVerifier) EnrichRulesWithVerifiedViews(rules ast.Rules) ast.Rules {
	cv.mu.RLock()
	defer cv.mu.RUnlock()

	newRules := rules
	newRules.RequireCatalogVerification = true
	newRules.VerifiedViews = make(map[string]bool)

	for _, v := range rules.Views {
		schema, name := SplitSchemaView(v.Name)
		key := CanonicalViewKey(schema, name)
		bareKey := strings.ToLower(name)

		if info, exists := cv.views[key]; exists && info.Status == StatusVerified {
			newRules.VerifiedViews[key] = true
			newRules.VerifiedViews[bareKey] = true
		} else {
			newRules.VerifiedViews[key] = false
			newRules.VerifiedViews[bareKey] = false
		}
	}

	return newRules
}

// VerifyStore verifies all views in the policy store against PostgreSQL catalog.
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
			if err := cv.VerifyRules(ctx, &rules); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}
