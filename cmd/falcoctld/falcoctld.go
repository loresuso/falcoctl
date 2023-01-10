package main

import (
	"context"
	"fmt"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/docker/docker/pkg/homedir"
	"github.com/falcosecurity/falcoctl/pkg/options"
	"github.com/falcosecurity/falcoctl/pkg/output"
	"github.com/spf13/cobra"
)

var (
	configFile string
)

func New(ctx context.Context) *cobra.Command {
	opt := options.NewOptions()
	opt.Initialize()

	cmd := &cobra.Command{
		Use:   "falcoctld",
		Short: "The control tool for installing artifacts of the Falco ecosystem",
	}

	cmd.AddCommand(NewRun(ctx, opt))

	return cmd
}

// Execute creates the root command and runs it.
func Execute() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)

	// If the ctx is marked as done then we reset the signals.
	go func() {
		<-ctx.Done()
		fmt.Printf("\nreceived signal, terminating...\n")
		stop()
	}()

	// we do not log the error here since we expect that each subcommand
	// handles the errors by itself.
	output.ExitOnErr(New(ctx).Execute())
}

func main() {
	Execute()
}

func init() {
	configFile = filepath.Join(homedir.Get(), ".config", "falcoctl", "config.yaml")
}
