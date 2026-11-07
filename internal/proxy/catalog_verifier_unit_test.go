package proxy

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tm-threemavithana/agentiam/internal/ast"
)

type mockCatalogReader struct {
	mu      sync.Mutex
	views   map[string]string // "schema.view" -> definition SQL
	kinds   map[string]rune   // "schema.rel" -> 'v', 'r', 'p', 'm', 'f'
	viewErr map[string]error
	kindErr map[string]error
}

func newMockCatalogReader() *mockCatalogReader {
	return &mockCatalogReader{
		views:   make(map[string]string),
		kinds:   make(map[string]rune),
		viewErr: make(map[string]error),
		kindErr: make(map[string]error),
	}
}

func (m *mockCatalogReader) QueryViewDefinition(ctx context.Context, schema, viewName string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := schema + "." + viewName
	if err, ok := m.viewErr[key]; ok && err != nil {
		return "", err
	}
	if def, ok := m.views[key]; ok {
		return def, nil
	}
	return "", fmt.Errorf("view '%s' does not exist in mock catalog", key)
}

func (m *mockCatalogReader) QueryRelationKind(ctx context.Context, schema, relName string) (rune, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := schema + "." + relName
	if err, ok := m.kindErr[key]; ok && err != nil {
		return 0, err
	}
	if k, ok := m.kinds[key]; ok {
		return k, nil
	}
	return 0, fmt.Errorf("relation '%s' does not exist in mock catalog", key)
}

// -----------------------------------------------------------------------------
// Priority A: Dependency Fail-Closed Tests
// -----------------------------------------------------------------------------

func TestCatalogVerifier_PriorityA_DependencyExtractionFailure_FailsClosed(t *testing.T) {
	mock := newMockCatalogReader()
	cv := NewCatalogVerifierWithReader(mock, nil)
	ctx := context.Background()

	// View with invalid SQL syntax
	malformedDef := "SELECT FROM WHERE 1 = ;"
	mock.views["public.bad_view"] = malformedDef
	mock.kinds["public.bad_view"] = 'v'

	fp, _ := ast.ComputeViewFingerprint(malformedDef)
	vp := ast.ViewPolicy{
		Name:                  "public.bad_view",
		BaseTable:             "customers",
		DefinitionFingerprint: fp,
	}

	_, err := cv.VerifyClientView(ctx, "client-1", 1, vp, nil, nil, nil, true)
	if err == nil {
		t.Fatalf("expected verification to fail closed on dependency extraction failure")
	}

	// Verify status is recorded as Error
	authKey := clientAuthKey("client-1", 1, "public", "bad_view")
	cv.mu.RLock()
	auth := cv.clientAuthCache[authKey]
	cv.mu.RUnlock()

	if auth == nil || auth.Status != StatusError {
		t.Fatalf("expected StatusError in cache, got %+v", auth)
	}
}

func TestCatalogVerifier_PriorityA_UnapprovedInnerView_FailsClosed(t *testing.T) {
	mock := newMockCatalogReader()
	cv := NewCatalogVerifierWithReader(mock, nil)
	ctx := context.Background()

	outerDef := "SELECT id, name FROM public.unapproved_inner;"
	outerFP, _ := ast.ComputeViewFingerprint(outerDef)
	mock.views["public.outer_view"] = outerDef
	mock.kinds["public.outer_view"] = 'v'
	mock.kinds["public.unapproved_inner"] = 'v' // It is a VIEW!

	outerVP := ast.ViewPolicy{
		Name:                  "public.outer_view",
		BaseTable:             "unapproved_inner",
		DefinitionFingerprint: outerFP,
		ColumnMappings: map[string]string{
			"id":   "id",
			"name": "name",
		},
	}
	// Policy map only contains outer_view, NOT unapproved_inner
	policyMap := map[string]ast.ViewPolicy{
		"public.outer_view": outerVP,
	}

	_, err := cv.VerifyClientView(ctx, "client-1", 1, outerVP, nil, policyMap, nil, true)
	if err == nil {
		t.Fatalf("expected verification to fail closed when dependency is an unapproved view")
	}
	if !errors.Is(err, err) && err.Error() == "" {
		t.Fatalf("expected non-empty error")
	}

	// Ensure outer view is NOT verified
	if cv.IsViewVerified("client-1", 1, "public", "outer_view") {
		t.Fatalf("outer_view must NOT be verified when inner view is unapproved")
	}
}

func TestCatalogVerifier_PriorityA_UnknownRelation_FailsClosed(t *testing.T) {
	mock := newMockCatalogReader()
	cv := NewCatalogVerifierWithReader(mock, nil)
	ctx := context.Background()

	outerDef := "SELECT id, name FROM public.ghost_table;"
	outerFP, _ := ast.ComputeViewFingerprint(outerDef)
	mock.views["public.outer_view"] = outerDef
	mock.kinds["public.outer_view"] = 'v'
	mock.kindErr["public.ghost_table"] = errors.New("relation ghost_table does not exist")

	outerVP := ast.ViewPolicy{
		Name:                  "public.outer_view",
		BaseTable:             "ghost_table",
		DefinitionFingerprint: outerFP,
		ColumnMappings: map[string]string{
			"id":   "id",
			"name": "name",
		},
	}

	_, err := cv.VerifyClientView(ctx, "client-1", 1, outerVP, nil, nil, nil, true)
	if err == nil {
		t.Fatalf("expected verification to fail closed when dependency lookup fails")
	}

	if cv.IsViewVerified("client-1", 1, "public", "outer_view") {
		t.Fatalf("outer_view must NOT be verified when dependency lookup fails")
	}
}

func TestCatalogVerifier_PriorityA_UnsupportedRelationType_FailsClosed(t *testing.T) {
	mock := newMockCatalogReader()
	cv := NewCatalogVerifierWithReader(mock, nil)
	ctx := context.Background()

	// 1. Materialized view dependency ('m')
	matDef := "SELECT id, name FROM public.mat_view;"
	matFP, _ := ast.ComputeViewFingerprint(matDef)
	mock.views["public.mat_dependent"] = matDef
	mock.kinds["public.mat_dependent"] = 'v'
	mock.kinds["public.mat_view"] = 'm' // Materialized view

	matVP := ast.ViewPolicy{
		Name:                  "public.mat_dependent",
		BaseTable:             "mat_view",
		DefinitionFingerprint: matFP,
		ColumnMappings:        map[string]string{"id": "id", "name": "name"},
	}

	_, err := cv.VerifyClientView(ctx, "client-1", 1, matVP, nil, nil, nil, true)
	if err == nil {
		t.Fatalf("expected verification to fail closed on materialized view dependency")
	}

	// 2. Foreign table dependency ('f')
	foreignDef := "SELECT id, name FROM public.foreign_table;"
	foreignFP, _ := ast.ComputeViewFingerprint(foreignDef)
	mock.views["public.foreign_dependent"] = foreignDef
	mock.kinds["public.foreign_dependent"] = 'v'
	mock.kinds["public.foreign_table"] = 'f' // Foreign table

	foreignVP := ast.ViewPolicy{
		Name:                  "public.foreign_dependent",
		BaseTable:             "foreign_table",
		DefinitionFingerprint: foreignFP,
		ColumnMappings:        map[string]string{"id": "id", "name": "name"},
	}

	_, err2 := cv.VerifyClientView(ctx, "client-1", 1, foreignVP, nil, nil, nil, true)
	if err2 == nil {
		t.Fatalf("expected verification to fail closed on foreign table dependency")
	}
}

func TestCatalogVerifier_PriorityA_AlteredInnerDependency_FailsClosed(t *testing.T) {
	mock := newMockCatalogReader()
	cv := NewCatalogVerifierWithReader(mock, nil)
	ctx := context.Background()

	baseDef := "SELECT id, name FROM customers;"
	baseFP, _ := ast.ComputeViewFingerprint(baseDef)

	// Inner view was approved with baseDef, but live catalog has drifted definition:
	driftedDef := "SELECT id, name, ssn FROM customers;"
	mock.views["public.inner_view"] = driftedDef
	mock.kinds["public.inner_view"] = 'v'
	mock.kinds["public.customers"] = 'r'

	outerDef := "SELECT id, name FROM public.inner_view;"
	outerFP, _ := ast.ComputeViewFingerprint(outerDef)
	mock.views["public.outer_view"] = outerDef
	mock.kinds["public.outer_view"] = 'v'

	innerVP := ast.ViewPolicy{
		Name:                  "public.inner_view",
		BaseTable:             "customers",
		DefinitionFingerprint: baseFP, // expects baseDef, not driftedDef!
		ColumnMappings:        map[string]string{"id": "id", "name": "name"},
	}
	outerVP := ast.ViewPolicy{
		Name:                  "public.outer_view",
		BaseTable:             "inner_view",
		DefinitionFingerprint: outerFP,
		ColumnMappings:        map[string]string{"id": "id", "name": "name"},
	}

	policyMap := map[string]ast.ViewPolicy{
		"public.inner_view": innerVP,
		"public.outer_view": outerVP,
	}

	_, err := cv.VerifyClientView(ctx, "client-1", 1, outerVP, nil, policyMap, nil, true)
	if err == nil {
		t.Fatalf("expected outer view verification to fail closed when inner view definition drifted")
	}

	if cv.IsViewVerified("client-1", 1, "public", "outer_view") {
		t.Fatalf("outer_view must NOT be verified when inner view is altered")
	}
	if cv.IsViewVerified("client-1", 1, "public", "inner_view") {
		t.Fatalf("inner_view must NOT be verified when its fingerprint drifts")
	}
}

func TestCatalogVerifier_PriorityA_ApprovedNestedDependencies_Succeeds(t *testing.T) {
	mock := newMockCatalogReader()
	cv := NewCatalogVerifierWithReader(mock, nil)
	ctx := context.Background()

	innerDef := "SELECT id, name FROM customers;"
	innerFP, _ := ast.ComputeViewFingerprint(innerDef)
	mock.views["public.inner_view"] = innerDef
	mock.kinds["public.inner_view"] = 'v'
	mock.kinds["public.customers"] = 'r' // Base table

	outerDef := "SELECT id, name FROM public.inner_view;"
	outerFP, _ := ast.ComputeViewFingerprint(outerDef)
	mock.views["public.outer_view"] = outerDef
	mock.kinds["public.outer_view"] = 'v'

	innerVP := ast.ViewPolicy{
		Name:                  "public.inner_view",
		BaseTable:             "customers",
		DefinitionFingerprint: innerFP,
		ColumnMappings:        map[string]string{"id": "id", "name": "name"},
	}
	outerVP := ast.ViewPolicy{
		Name:                  "public.outer_view",
		BaseTable:             "inner_view",
		DefinitionFingerprint: outerFP,
		ColumnMappings:        map[string]string{"id": "id", "name": "name"},
	}

	policyMap := map[string]ast.ViewPolicy{
		"public.inner_view": innerVP,
		"public.outer_view": outerVP,
	}

	auth, err := cv.VerifyClientView(ctx, "client-1", 1, outerVP, nil, policyMap, nil, true)
	if err != nil {
		t.Fatalf("expected valid nested view verification to succeed, got: %v", err)
	}

	if auth.Status != StatusVerified {
		t.Fatalf("expected StatusVerified, got: %s", auth.Status)
	}
	if len(auth.Dependencies) != 1 || auth.Dependencies[0] != "public.inner_view" {
		t.Fatalf("expected dependencies [public.inner_view], got: %v", auth.Dependencies)
	}

	if !cv.IsViewVerified("client-1", 1, "public", "outer_view") {
		t.Fatalf("expected outer_view to be verified in cache")
	}
	if !cv.IsViewVerified("client-1", 1, "public", "inner_view") {
		t.Fatalf("expected inner_view to also be verified in cache")
	}
}

// -----------------------------------------------------------------------------
// Priority B: Concurrency Ordering & Generation Barrier Tests
// -----------------------------------------------------------------------------

func TestCatalogVerifier_PriorityB_StaleVerifiedCannotOverwriteNewerFailure(t *testing.T) {
	mock := newMockCatalogReader()
	cv := NewCatalogVerifierWithReader(mock, nil)
	ctx := context.Background()

	viewDef := "SELECT id, name FROM customers;"
	fp, _ := ast.ComputeViewFingerprint(viewDef)
	mock.views["public.reports"] = viewDef
	mock.kinds["public.reports"] = 'v'
	mock.kinds["public.customers"] = 'r'

	vp := ast.ViewPolicy{
		Name:                  "public.reports",
		BaseTable:             "customers",
		DefinitionFingerprint: fp,
		ColumnMappings:        map[string]string{"id": "id", "name": "name"},
	}

	// Setup barrier hook to pause the in-flight verification before writing StatusVerified
	reachedHook := make(chan struct{})
	unblockWrite := make(chan struct{})

	cv.SetBeforeAuthWriteHook(func(clientID, schema, viewName string) {
		if viewName == "reports" {
			close(reachedHook)
			<-unblockWrite
		}
	})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		cv.VerifyClientView(ctx, "client-1", 1, vp, nil, nil, nil, true)
	}()

	// Wait until in-flight verification has completed catalog queries and is waiting to write
	<-reachedHook

	// While goroutine is paused, main thread writes a newer failure (StatusDriftDetected)
	authKey := clientAuthKey("client-1", 1, "public", "reports")
	time.Sleep(10 * time.Millisecond) // ensure newer timestamp
	cv.mu.Lock()
	driftErr := errors.New("concurrent schema drift detected")
	cv.clientAuthCache[authKey] = &ClientViewAuthorization{
		ClientID:            "client-1",
		PolicyVersion:       1,
		CanonicalSchema:     "public",
		CanonicalName:       "reports",
		ExpectedFingerprint: fp,
		ActualFingerprint:   "sha256:drifted",
		Status:              StatusDriftDetected,
		VerifiedAt:          time.Now(),
		LastError:           driftErr,
	}
	cv.mu.Unlock()

	// Now unblock the older in-flight verification
	close(unblockWrite)
	wg.Wait()

	// Clear hook
	cv.SetBeforeAuthWriteHook(nil)

	// Concurrency guard MUST preserve the newer failure! Stale StatusVerified must NOT overwrite!
	cv.mu.RLock()
	finalAuth := cv.clientAuthCache[authKey]
	cv.mu.RUnlock()

	if finalAuth == nil || finalAuth.Status != StatusDriftDetected {
		t.Fatalf("CRITICAL: Stale in-flight StatusVerified overwrote newer failure! Final status: %v", finalAuth)
	}
}

func TestCatalogVerifier_PriorityB_InvalidationCannotBeUndoneByInFlightVerification(t *testing.T) {
	mock := newMockCatalogReader()
	cv := NewCatalogVerifierWithReader(mock, nil)
	ctx := context.Background()

	viewDef := "SELECT id, name FROM customers;"
	fp, _ := ast.ComputeViewFingerprint(viewDef)
	mock.views["public.reports"] = viewDef
	mock.kinds["public.reports"] = 'v'
	mock.kinds["public.customers"] = 'r'

	vp := ast.ViewPolicy{
		Name:                  "public.reports",
		BaseTable:             "customers",
		DefinitionFingerprint: fp,
		ColumnMappings:        map[string]string{"id": "id", "name": "name"},
	}

	reachedHook := make(chan struct{})
	unblockWrite := make(chan struct{})

	cv.SetBeforeAuthWriteHook(func(clientID, schema, viewName string) {
		if viewName == "reports" {
			close(reachedHook)
			<-unblockWrite
		}
	})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		cv.VerifyClientView(ctx, "client-1", 1, vp, nil, nil, nil, true)
	}()

	// Wait until goroutine is paused before writing auth
	<-reachedHook

	// Invalidate view concurrently
	cv.InvalidateView("public", "reports")

	// Unblock goroutine
	close(unblockWrite)
	wg.Wait()
	cv.SetBeforeAuthWriteHook(nil)

	// View MUST NOT be verified after invalidation
	if cv.IsViewVerified("client-1", 1, "public", "reports") {
		t.Fatalf("CRITICAL: Stale in-flight verification restored StatusVerified after InvalidateView!")
	}
}

func TestCatalogVerifier_PriorityB_StaleCatalogSnapshotCannotOverwriteNewerSnapshot(t *testing.T) {
	mock := newMockCatalogReader()
	cv := NewCatalogVerifierWithReader(mock, nil)
	ctx := context.Background()

	def1 := "SELECT id FROM customers;"
	def2 := "SELECT id, name FROM customers;"

	mock.views["public.reports"] = def1
	mock.kinds["public.reports"] = 'v'

	reachedHook := make(chan struct{})
	unblockWrite := make(chan struct{})
	var hookCalled atomic.Bool

	cv.SetBeforeSnapshotWriteHook(func(schema, viewName string) {
		if viewName == "reports" {
			if hookCalled.CompareAndSwap(false, true) {
				close(reachedHook)
				<-unblockWrite
			}
		}
	})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		cv.QueryCatalogSnapshot(ctx, "public", "reports", true)
	}()

	<-reachedHook

	// While thread 1 is paused with def1, main thread updates mock to def2 and queries snapshot
	mock.mu.Lock()
	mock.views["public.reports"] = def2
	mock.mu.Unlock()
	cv.InvalidateView("public", "reports") // advances generation!

	// Main thread snapshots def2
	snap2, err := cv.QueryCatalogSnapshot(ctx, "public", "reports", true)
	if err != nil {
		t.Fatalf("unexpected error fetching newer snapshot: %v", err)
	}

	// Now unblock thread 1 (which has def1)
	close(unblockWrite)
	wg.Wait()
	cv.SetBeforeSnapshotWriteHook(nil)

	// Check cached snapshot: MUST be def2, not def1!
	cv.mu.RLock()
	cachedSnap := cv.catalogCache["public.reports"]
	cv.mu.RUnlock()

	if cachedSnap == nil || cachedSnap.DefinitionSQL != def2 {
		t.Fatalf("CRITICAL: Stale snapshot def1 overwrote newer snapshot def2! Got: %+v, expected def2: %s, snap2: %+v", cachedSnap, def2, snap2)
	}
}

func TestCatalogVerifier_PriorityB_ConcurrentMultiClientRefreshUnderDDL(t *testing.T) {
	mock := newMockCatalogReader()
	cv := NewCatalogVerifierWithReader(mock, nil)
	ctx := context.Background()

	defA := "SELECT id, name FROM customers;"
	fpA, _ := ast.ComputeViewFingerprint(defA)
	mock.views["public.reports"] = defA
	mock.kinds["public.reports"] = 'v'
	mock.kinds["public.customers"] = 'r'

	clients := []string{"agent-1", "agent-2", "agent-3"}
	vp := ast.ViewPolicy{
		Name:                  "public.reports",
		BaseTable:             "customers",
		DefinitionFingerprint: fpA,
		ColumnMappings:        map[string]string{"id": "id", "name": "name"},
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// 10 worker goroutines performing verification, freshness checks, and queries
	for i := 0; i < 10; i++ {
		wg.Add(1)
		clientID := clients[i%len(clients)]
		go func(cid string) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = cv.IsViewVerified(cid, 1, "public", "reports")
					_, _ = cv.VerifyClientView(ctx, cid, 1, vp, nil, nil, nil, false)
					time.Sleep(1 * time.Millisecond)
				}
			}
		}(clientID)
	}

	// DDL mutator goroutine simulating concurrent schema changes and invalidations
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			time.Sleep(2 * time.Millisecond)
			cv.InvalidateView("public", "reports")
		}
	}()

	time.Sleep(60 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// -----------------------------------------------------------------------------
// Priority C: Canonical Identity Correctness Tests
// -----------------------------------------------------------------------------

func TestCatalogVerifier_PriorityC_QuotedVsUnquoted(t *testing.T) {
	mock := newMockCatalogReader()
	cv := NewCatalogVerifierWithReader(mock, nil)
	ctx := context.Background()

	// Two distinct views in PostgreSQL:
	// 1. public.reports (unquoted, folded to lowercase)
	// 2. public."Reports" (quoted, case preserved)
	unquotedDef := "SELECT id, name FROM customers;"
	unquotedFP, _ := ast.ComputeViewFingerprint(unquotedDef)

	quotedDef := "SELECT id, ssn, name FROM customers;"
	quotedFP, _ := ast.ComputeViewFingerprint(quotedDef)

	mock.views["public.reports"] = unquotedDef
	mock.kinds["public.reports"] = 'v'

	mock.views["public.Reports"] = quotedDef
	mock.kinds["public.Reports"] = 'v'

	mock.kinds["public.customers"] = 'r'

	vpUnquoted := ast.ViewPolicy{
		Name:                  "public.reports",
		BaseTable:             "customers",
		DefinitionFingerprint: unquotedFP,
		ColumnMappings:        map[string]string{"id": "id", "name": "name"},
	}
	vpQuoted := ast.ViewPolicy{
		Name:                  "public.\"Reports\"",
		BaseTable:             "customers",
		DefinitionFingerprint: quotedFP,
		ColumnMappings:        map[string]string{"id": "id", "name": "name", "ssn": "ssn"},
	}

	// Verify unquoted view
	auth1, err1 := cv.VerifyClientView(ctx, "client-1", 1, vpUnquoted, nil, nil, nil, true)
	if err1 != nil {
		t.Fatalf("unexpected error verifying unquoted view: %v", err1)
	}
	if auth1.Status != StatusVerified {
		t.Fatalf("expected unquoted view to be verified")
	}

	// Verify quoted view
	auth2, err2 := cv.VerifyClientView(ctx, "client-1", 1, vpQuoted, nil, nil, nil, true)
	if err2 != nil {
		t.Fatalf("unexpected error verifying quoted view: %v", err2)
	}
	if auth2.Status != StatusVerified {
		t.Fatalf("expected quoted view to be verified")
	}

	// Invalidate ONLY quoted view
	cv.InvalidateView("public", "\"Reports\"")

	// Check isolation:
	// Quoted view must be unverified
	if cv.IsViewVerified("client-1", 1, "public", "\"Reports\"") {
		t.Fatalf("quoted view public.\"Reports\" must NOT be verified after invalidation")
	}
	// Unquoted view must STILL be verified!
	if !cv.IsViewVerified("client-1", 1, "public", "reports") {
		t.Fatalf("unquoted view public.reports must REMAIN verified!")
	}
}

func TestCatalogVerifier_PriorityC_ClientIDsDifferingOnlyByCase(t *testing.T) {
	mock := newMockCatalogReader()
	cv := NewCatalogVerifierWithReader(mock, nil)
	ctx := context.Background()

	def := "SELECT id, name FROM customers;"
	fp, _ := ast.ComputeViewFingerprint(def)
	mock.views["public.reports"] = def
	mock.kinds["public.reports"] = 'v'
	mock.kinds["public.customers"] = 'r'

	vp := ast.ViewPolicy{
		Name:                  "public.reports",
		BaseTable:             "customers",
		DefinitionFingerprint: fp,
		ColumnMappings:        map[string]string{"id": "id", "name": "name"},
	}

	// Verify for client "agent-alpha"
	_, err := cv.VerifyClientView(ctx, "agent-alpha", 1, vp, nil, nil, nil, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check if "AGENT-ALPHA" is verified -> MUST BE FALSE!
	if cv.IsViewVerified("AGENT-ALPHA", 1, "public", "reports") {
		t.Fatalf("CRITICAL: Case-insensitive client ID merged! 'AGENT-ALPHA' must NOT inherit 'agent-alpha' authorization!")
	}

	// Now verify for "AGENT-ALPHA"
	_, err2 := cv.VerifyClientView(ctx, "AGENT-ALPHA", 1, vp, nil, nil, nil, true)
	if err2 != nil {
		t.Fatalf("unexpected error: %v", err2)
	}

	if !cv.IsViewVerified("AGENT-ALPHA", 1, "public", "reports") {
		t.Fatalf("AGENT-ALPHA should now be verified")
	}

	// Both are verified independently in cache
	cv.mu.RLock()
	keyLower := clientAuthKey("agent-alpha", 1, "public", "reports")
	keyUpper := clientAuthKey("AGENT-ALPHA", 1, "public", "reports")
	authLower := cv.clientAuthCache[keyLower]
	authUpper := cv.clientAuthCache[keyUpper]
	cv.mu.RUnlock()

	if authLower == nil || authUpper == nil {
		t.Fatalf("expected separate cache entries for distinct client IDs")
	}
	if keyLower == keyUpper {
		t.Fatalf("cache keys for differing case client IDs must be distinct")
	}
}

func TestCatalogVerifier_PriorityC_QuotedMixedCaseSchema(t *testing.T) {
	mock := newMockCatalogReader()
	cv := NewCatalogVerifierWithReader(mock, nil)
	ctx := context.Background()

	def := "SELECT id FROM \"FinanceDB\".customers;"
	fp, _ := ast.ComputeViewFingerprint(def)

	mock.views["FinanceDB.Transactions"] = def
	mock.kinds["FinanceDB.Transactions"] = 'v'
	mock.kinds["FinanceDB.customers"] = 'r'

	vp := ast.ViewPolicy{
		Name:                  "\"FinanceDB\".\"Transactions\"",
		BaseTable:             "customers",
		DefinitionFingerprint: fp,
		ColumnMappings:        map[string]string{"id": "id"},
	}

	auth, err := cv.VerifyClientView(ctx, "client-1", 1, vp, nil, nil, nil, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if auth.Status != StatusVerified {
		t.Fatalf("expected StatusVerified for quoted mixed-case schema view")
	}

	if !cv.IsViewVerified("client-1", 1, "\"FinanceDB\"", "\"Transactions\"") {
		t.Fatalf("expected quoted schema view to be verified")
	}
	// Unquoted lowercase schema must NOT match!
	if cv.IsViewVerified("client-1", 1, "financedb", "transactions") {
		t.Fatalf("financedb.transactions must NOT match \"FinanceDB\".\"Transactions\"")
	}
}

func TestCatalogVerifier_PriorityC_SameUnqualifiedNameInDifferentSchemas(t *testing.T) {
	mock := newMockCatalogReader()
	cv := NewCatalogVerifierWithReader(mock, nil)
	ctx := context.Background()

	def1 := "SELECT id FROM schema_a.customers_a;"
	fp1, _ := ast.ComputeViewFingerprint(def1)
	mock.views["schema_a.orders"] = def1
	mock.kinds["schema_a.orders"] = 'v'
	mock.kinds["schema_a.customers_a"] = 'r'

	def2 := "SELECT id, total FROM schema_b.customers_b;"
	fp2, _ := ast.ComputeViewFingerprint(def2)
	mock.views["schema_b.orders"] = def2
	mock.kinds["schema_b.orders"] = 'v'
	mock.kinds["schema_b.customers_b"] = 'r'

	vpA := ast.ViewPolicy{
		Name:                  "schema_a.orders",
		BaseTable:             "customers_a",
		DefinitionFingerprint: fp1,
		ColumnMappings:        map[string]string{"id": "id"},
	}
	vpB := ast.ViewPolicy{
		Name:                  "schema_b.orders",
		BaseTable:             "customers_b",
		DefinitionFingerprint: fp2,
		ColumnMappings:        map[string]string{"id": "id", "total": "total"},
	}

	// Verify schema_a.orders
	_, errA := cv.VerifyClientView(ctx, "client-1", 1, vpA, nil, nil, nil, true)
	if errA != nil {
		t.Fatalf("unexpected error: %v", errA)
	}

	// Verify schema_b.orders
	_, errB := cv.VerifyClientView(ctx, "client-1", 1, vpB, nil, nil, nil, true)
	if errB != nil {
		t.Fatalf("unexpected error: %v", errB)
	}

	// Invalidate schema_a.orders
	cv.InvalidateView("schema_a", "orders")

	if cv.IsViewVerified("client-1", 1, "schema_a", "orders") {
		t.Fatalf("schema_a.orders must be unverified")
	}
	if !cv.IsViewVerified("client-1", 1, "schema_b", "orders") {
		t.Fatalf("schema_b.orders must remain verified")
	}
}

func TestCatalogVerifier_PriorityC_MatchingAndMismatchingFingerprints(t *testing.T) {
	validFP := "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	validUpper := "SHA256:E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
	differentFP := "sha256:1111111111111111111111111111111111111111111111111111111111111111"

	if !ast.CompareFingerprints(validFP, validFP) {
		t.Fatalf("identical fingerprints must match")
	}
	if !ast.CompareFingerprints(validFP, validUpper) {
		t.Fatalf("fingerprints must match case-insensitively")
	}
	if ast.CompareFingerprints(validFP, differentFP) {
		t.Fatalf("differing fingerprints must NOT match")
	}
	if ast.CompareFingerprints("", validFP) {
		t.Fatalf("empty expected fingerprint must NOT match")
	}
	if ast.CompareFingerprints(validFP, "") {
		t.Fatalf("empty actual fingerprint must NOT match")
	}
}
