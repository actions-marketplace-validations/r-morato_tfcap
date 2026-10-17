//go:build !linux

package sandbox

import (
	"errors"
	"io"
	"time"
)

const ChildArg = "__sandbox-child"

type Options struct {
	Dir     string
	Command []string
	Timeout time.Duration
	Self    string
	Stdout  io.Writer
	Stderr  io.Writer
}

type Result struct {
	Events   []Event  `json:"events"`
	ExitCode int      `json:"exit_code"`
	Strace   bool     `json:"strace"`
	Notes    []string `json:"notes,omitempty"`
	TimedOut bool     `json:"timed_out,omitempty"`
}

var errUnsupported = errors.New("tfcap sandbox needs Linux namespaces; run it on a Linux CI runner or VM")

func Supported() error             { return errUnsupported }
func Run(Options) (*Result, error) { return nil, errUnsupported }
func Child()                       {}
