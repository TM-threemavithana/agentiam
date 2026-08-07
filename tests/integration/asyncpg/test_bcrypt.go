package main

import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	pwd := "Test Agent"
	hash, _ := bcrypt.GenerateFromPassword([]byte(pwd), 10)
	fmt.Println(string(hash))
}
