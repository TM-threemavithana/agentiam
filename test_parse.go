package main

import (
	"fmt"
	"github.com/wasilibs/go-pgquery/parser"
	pg_query "github.com/pganalyze/pg_query_go/v6"
	"google.golang.org/protobuf/proto"
)

func main() {
	sql := "SELECT * FROM users WHERE id = 1 AND (SELECT pg_sleep(10)) IS NULL;"
	b, _ := parser.ParseToProtobuf(sql)
	var tree pg_query.ParseResult
	proto.Unmarshal(b, &tree)
	fmt.Printf("%+v\n", tree.Stmts[0].Stmt)
}
