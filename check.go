package main
import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
)
func main() {
	hash := "$2a$10$zmUdNg9T6RWlvx8e9CVpZeSNtYkUQUjRhSfXazCmATEMNyevxybbe"
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("test-agent-key"))
	if err != nil {
		fmt.Println("Does not match:", err)
	} else {
		fmt.Println("Matches!")
	}
}
