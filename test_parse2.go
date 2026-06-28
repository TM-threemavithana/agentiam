package main

import (
	"fmt"
	"github.com/wasilibs/go-pgquery/parser"
	pg_query "github.com/pganalyze/pg_query_go/v6"
	"google.golang.org/protobuf/proto"
	"reflect"
)

func walkChildren(v interface{}) {
	if v == nil {
		return
	}
	val := reflect.ValueOf(v)
	if !val.IsValid() {
		return
	}
	if val.Kind() == reflect.Ptr || val.Kind() == reflect.Interface {
		if val.IsNil() {
			return
		}
		walkChildren(val.Elem().Interface())
		return
	}
	if val.Kind() == reflect.Struct {
		for i := 0; i < val.NumField(); i++ {
			field := val.Field(i)
			if !field.CanInterface() {
				continue
			}
			if field.Kind() == reflect.Ptr && !field.IsNil() {
				if n, ok := field.Interface().(*pg_query.Node); ok {
					enforceRules(n)
					continue
				}
			}
			walkChildren(field.Interface())
		}
	} else if val.Kind() == reflect.Slice {
		for i := 0; i < val.Len(); i++ {
			elem := val.Index(i)
			if elem.Kind() == reflect.Ptr && !elem.IsNil() {
				if n, ok := elem.Interface().(*pg_query.Node); ok {
					enforceRules(n)
					continue
				}
			}
			walkChildren(elem.Interface())
		}
	}
}

func enforceRules(node *pg_query.Node) {
	switch n := node.Node.(type) {
	case *pg_query.Node_FuncCall:
		fmt.Printf("HIT FUNCCALL\n")
		for _, fn := range n.FuncCall.Funcname {
			if strNode, ok := fn.Node.(*pg_query.Node_String_); ok {
				fmt.Printf("FUNC NAME: %s\n", strNode.String_.Sval)
			}
		}
	}
	walkChildren(node.Node)
}

func main() {
	sql := "SELECT * FROM users WHERE id = 1 AND (SELECT pg_sleep(10)) IS NULL;"
	b, _ := parser.ParseToProtobuf(sql)
	var tree pg_query.ParseResult
	proto.Unmarshal(b, &tree)
	enforceRules(tree.Stmts[0].Stmt)
}
