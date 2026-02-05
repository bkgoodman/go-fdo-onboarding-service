// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0
// Author: Brad Goodman

package main

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// ExternalCommandExecutor handles execution of external commands with variable substitution
type ExternalCommandExecutor struct {
	commandTemplate string
	timeout         time.Duration
}

// NewExternalCommandExecutor creates a new external command executor
func NewExternalCommandExecutor(commandTemplate string, timeout time.Duration) *ExternalCommandExecutor {
	return &ExternalCommandExecutor{
		commandTemplate: commandTemplate,
		timeout:         timeout,
	}
}

// Execute runs the external command with variable substitution
func (e *ExternalCommandExecutor) Execute(ctx context.Context, variables map[string]string) (string, error) {
	// Prepare command with variable substitution
	command := e.commandTemplate
	for key, value := range variables {
		command = strings.ReplaceAll(command, "{"+key+"}", value)
	}

	fmt.Printf(" DEBUG: ExternalExecutor.Execute command=%s\n", command)

	// Execute command with timeout
	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf(" DEBUG: External command failed: %v, output: %s\n", err, string(output))
		return "", fmt.Errorf("external command failed: %w, output: %s", err, string(output))
	}

	fmt.Printf(" DEBUG: External command success, output: %s\n", string(output))
	return string(output), nil
}
