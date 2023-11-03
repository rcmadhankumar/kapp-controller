// Copyright 2022 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package local

import (
	"fmt"
	"io"
	goexec "os/exec"
	"strings"

	"github.com/vmware-tanzu/carvel-kapp-controller/pkg/exec"
)

type DetailedCmdRunner struct {
	log        io.Writer
	fullOutput bool
}

var _ exec.CmdRunner = &DetailedCmdRunner{}

func NewDetailedCmdRunner(log io.Writer, fullOutput bool) *DetailedCmdRunner {
	return &DetailedCmdRunner{log, fullOutput}
}

func (r DetailedCmdRunner) Run(cmd *goexec.Cmd) error {
	if r.fullOutput {
		cmd.Stdout = io.MultiWriter(r.log, cmd.Stdout)
		cmd.Stderr = io.MultiWriter(r.log, cmd.Stderr)
	}

	fmt.Fprintf(r.log, "==> Executing %s %v\n", cmd.Path, cmd.Args)
	defer fmt.Fprintf(r.log, "==> Finished executing %s\n\n", cmd.Path)

	return exec.PlainCmdRunner{}.Run(cmd)
}

func (r DetailedCmdRunner) RunWithCancel(cmd *goexec.Cmd, cancelCh chan struct{}) error {
	if r.fullOutput {
		cmd.Stdout = io.MultiWriter(r.log, cmd.Stdout)
		cmd.Stderr = io.MultiWriter(r.log, cmd.Stderr)
	}

	if strings.Contains(cmd.Args[0], "kapp") {
		fmt.Printf("Here's the kapp command")
		// Edit the command (change the command and its arguments)
		fmt.Printf("\n ====== > cmd.path %+v", cmd.Path)
		fmt.Printf("\n ====== > cmd.args %+v", cmd.Args)
		fmt.Printf("\n ====== > cmd.Env %+v", cmd.Env)

		path, err := goexec.LookPath("tanzu")
		if err != nil {
			fmt.Printf("Error: %+v", err)
		}

		fmt.Printf("\n Lookpath : %s", path)

		modifiedCmd := &goexec.Cmd{
			Path:   path,
			Args:   append([]string{"tanzu"}, cmd.Args...),
			Env:    cmd.Env, // Copy the environment variables
			Stdin:  cmd.Stdin,
			Stdout: cmd.Stdout,
			Stderr: cmd.Stdout,
		}

		fmt.Fprintf(r.log, "==> Executing %s %v\n", cmd.Path, cmd.Args)
		defer fmt.Fprintf(r.log, "==> Finished executing %s\n\n", cmd.Path)
		return exec.PlainCmdRunner{}.RunWithCancel(modifiedCmd, cancelCh)

	}

	fmt.Fprintf(r.log, "==> Executing %s %v\n", cmd.Path, cmd.Args)
	defer fmt.Fprintf(r.log, "==> Finished executing %s\n\n", cmd.Path)

	return exec.PlainCmdRunner{}.RunWithCancel(cmd, cancelCh)
}
