package main
import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
)
func main() {
	hash, _ := bcrypt.GenerateFromPassword([]byte("test-agent-secret"), bcrypt.DefaultCost)
	fmt.Println(string(hash))
}
