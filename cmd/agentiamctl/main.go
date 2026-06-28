package main

import (
	"github.com/tm-threemavithana/agentiam/internal/policy"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

var policyFile string

func loadPolicies() (*policy.PoliciesYAML, error) {
	b, err := os.ReadFile(policyFile)
	if err != nil {
		if os.IsNotExist(err) {
			return &policy.PoliciesYAML{Version: "1"}, nil
		}
		return nil, err
	}

	var py policy.PoliciesYAML
	if err := yaml.Unmarshal(b, &py); err != nil {
		return nil, err
	}
	return &py, nil
}

func savePolicies(py *policy.PoliciesYAML) error {
	b, err := yaml.Marshal(py)
	if err != nil {
		return err
	}
	return os.WriteFile(policyFile, b, 0644)
}

func generateSecureKey() string {
	b := make([]byte, 16)
	rand.Read(b)
	return "sk-" + hex.EncodeToString(b)
}

func main() {
	var rootCmd = &cobra.Command{Use: "agentiamctl"}
	rootCmd.PersistentFlags().StringVarP(&policyFile, "file", "f", "policies.yaml", "Path to policies YAML file")

	var keysCmd = &cobra.Command{Use: "keys"}
	rootCmd.AddCommand(keysCmd)

	// CREATE
	var agentName string
	var allowedOps string
	var allowedTables string
	var selectLimit int

	var createCmd = &cobra.Command{
		Use:   "create",
		Short: "Create a new agent key",
		RunE: func(cmd *cobra.Command, args []string) error {
			if agentName == "" {
				return fmt.Errorf("--agent name is required")
			}

			py, err := loadPolicies()
			if err != nil {
				return err
			}

			for _, a := range py.Agents {
				if a.Name == agentName {
					return fmt.Errorf("agent '%s' already exists", agentName)
				}
			}

			plaintextKey := generateSecureKey()
			hash, err := bcrypt.GenerateFromPassword([]byte(plaintextKey), bcrypt.DefaultCost)
			if err != nil {
				return err
			}

			ops := []string{}
			if allowedOps != "" {
				for _, op := range strings.Split(allowedOps, ",") {
					ops = append(ops, strings.TrimSpace(op))
				}
			}

			tables := []string{}
			if allowedTables != "" {
				for _, t := range strings.Split(allowedTables, ",") {
					tables = append(tables, strings.TrimSpace(t))
				}
			}

			newAgent := policy.AgentConfig{
				Name:              agentName,
				Key:               string(hash),
				AllowedStatements: ops,
				AllowedTables:     tables,
				SelectLimit:       selectLimit,
				CreatedAt:         time.Now().UTC().Format(time.RFC3339),
			}

			py.Agents = append(py.Agents, newAgent)

			if err := savePolicies(py); err != nil {
				return err
			}

			fmt.Printf("Successfully created agent: %s\n", agentName)
			fmt.Printf("API Key: %s\n", plaintextKey)
			fmt.Println("IMPORTANT: Save this key now! It will not be shown again.")
			return nil
		},
	}
	createCmd.Flags().StringVar(&agentName, "agent", "", "Agent name")
	createCmd.Flags().StringVar(&allowedOps, "allow", "", "Comma separated allowed statements (e.g. SELECT,INSERT)")
	createCmd.Flags().StringVar(&allowedTables, "tables", "", "Comma separated allowed tables")
	createCmd.Flags().IntVar(&selectLimit, "limit", 100, "Select limit")
	keysCmd.AddCommand(createCmd)

	// LIST
	var listCmd = &cobra.Command{
		Use:   "list",
		Short: "List all agents",
		RunE: func(cmd *cobra.Command, args []string) error {
			py, err := loadPolicies()
			if err != nil {
				return err
			}
			fmt.Printf("%-20s %-30s %-10s %-25s\n", "NAME", "ALLOWED OPS", "LIMIT", "CREATED AT")
			fmt.Println(strings.Repeat("-", 90))
			for _, a := range py.Agents {
				fmt.Printf("%-20s %-30s %-10d %-25s\n", a.Name, strings.Join(a.AllowedStatements, ","), a.SelectLimit, a.CreatedAt)
			}
			return nil
		},
	}
	keysCmd.AddCommand(listCmd)

	// REVOKE
	var revokeCmd = &cobra.Command{
		Use:   "revoke",
		Short: "Revoke an agent key",
		RunE: func(cmd *cobra.Command, args []string) error {
			if agentName == "" {
				return fmt.Errorf("--agent name is required")
			}

			py, err := loadPolicies()
			if err != nil {
				return err
			}

			found := false
			newAgents := []policy.AgentConfig{}
			for _, a := range py.Agents {
				if a.Name == agentName {
					found = true
				} else {
					newAgents = append(newAgents, a)
				}
			}

			if !found {
				return fmt.Errorf("agent '%s' not found", agentName)
			}

			py.Agents = newAgents
			if err := savePolicies(py); err != nil {
				return err
			}

			fmt.Printf("Successfully revoked agent: %s\n", agentName)
			return nil
		},
	}
	revokeCmd.Flags().StringVar(&agentName, "agent", "", "Agent name")
	keysCmd.AddCommand(revokeCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
