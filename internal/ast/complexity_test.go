package ast

import (
	"testing"

	pg_query "github.com/pganalyze/pg_query_go/v6"
	"github.com/wasilibs/go-pgquery/parser"
	"google.golang.org/protobuf/proto"
	tidb "github.com/pingcap/tidb/pkg/parser"
)

func TestPostgresComplexity(t *testing.T) {
	// Simple select
	simpleSQL := "SELECT * FROM users WHERE id = 1"
	b, _ := parser.ParseToProtobuf(simpleSQL)
	var tree pg_query.ParseResult
	_ = proto.Unmarshal(b, &tree)
	simpleScore := CalculatePostgresComplexity(tree.Stmts[0].Stmt)

	// Complex join select
	complexSQL := "SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id WHERE o.total > 100 ORDER BY o.total DESC"
	b2, _ := parser.ParseToProtobuf(complexSQL)
	var tree2 pg_query.ParseResult
	_ = proto.Unmarshal(b2, &tree2)
	complexScore := CalculatePostgresComplexity(tree2.Stmts[0].Stmt)

	if complexScore <= simpleScore {
		t.Errorf("expected complex score (%d) to be higher than simple score (%d)", complexScore, simpleScore)
	}
}

func TestMySQLComplexity(t *testing.T) {
	pr := tidb.New()
	
	// Simple
	stmts, _, _ := pr.Parse("SELECT * FROM users", "", "")
	cv := &complexityVisitor{}
	stmts[0].Accept(cv)
	simpleScore := cv.score

	// Join
	stmts2, _, _ := pr.Parse("SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id", "", "")
	cv2 := &complexityVisitor{}
	stmts2[0].Accept(cv2)
	complexScore := cv2.score

	if complexScore <= simpleScore {
		t.Errorf("expected MySQL complex score (%d) to be higher than simple score (%d)", complexScore, simpleScore)
	}
}
