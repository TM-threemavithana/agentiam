package main

import (
	"fmt"
	"io/ioutil"
	"gopkg.in/yaml.v3"
)

type AgentConfig struct {
	BlockedFunctions []string `yaml:"blocked_functions"`
}
type PoliciesYAML struct {
	Agents []AgentConfig `yaml:"agents"`
}

func main() {
	b, _ := ioutil.ReadFile("demo/policies.yaml")
	var py PoliciesYAML
	yaml.Unmarshal(b, &py)
	fmt.Printf("BlockedFunctions: %v\n", py.Agents[0].BlockedFunctions)
}
