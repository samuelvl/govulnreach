package cmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"

	"github.com/samuelvl/govulnreach/internal/advisory"
	"github.com/samuelvl/govulnreach/internal/analyze"
	"github.com/samuelvl/govulnreach/internal/source"
	"github.com/samuelvl/govulnreach/internal/vex"
)

type AdvisoryLoader interface {
	Load(context.Context, string, string) (*advisory.Advisory, error)
}

type SourceLoader interface {
	Load(context.Context, string) (*source.Workspace, error)
}

type Dependencies struct {
	Advisories AdvisoryLoader
	Sources    SourceLoader
}

func NewDependencies() Dependencies {
	return Dependencies{
		Advisories: advisory.NewLoader(),
	}
}

// Run analyzes a local Go main package and writes one OpenVEX document.
func Run(args []string, stdout, stderr io.Writer) error {
	return run(context.Background(), NewDependencies(), args, stdout, stderr)
}

func run(ctx context.Context, dependencies Dependencies, args []string, stdout, stderr io.Writer) (runErr error) {
	flags := flag.NewFlagSet("govulnreach", flag.ContinueOnError)
	flags.SetOutput(stderr)
	logLevel := flags.String("log-level", "info", "log level: debug, info, warn, or error")
	sourceReference := flags.String("source", ".", "local directory or public GitHub HTTPS URL")
	packagePattern := flags.String("package", ".", "main package pattern relative to source")
	advisoryReference := flags.String("advisory", "", "local OSV file or OSV ID (required)")
	advisoryFormat := flags.String("advisory-format", "osv", "advisory format")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %v", flags.Args())
	}
	level, err := parseLogLevel(*logLevel)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level}))
	if *advisoryReference == "" {
		return errors.New("--advisory is required")
	}

	if dependencies.Advisories == nil {
		dependencies.Advisories = advisory.NewLoader()
	}
	adv, err := dependencies.Advisories.Load(ctx, *advisoryReference, *advisoryFormat)
	if err != nil {
		return err
	}
	logger.Info("loaded advisory", "reference", *advisoryReference, "id", adv.ID)
	if dependencies.Sources == nil {
		dependencies.Sources = source.NewLoader(logger)
	}
	logger.Info("loading source", "source", *sourceReference)
	workspace, err := dependencies.Sources.Load(ctx, *sourceReference)
	if err != nil {
		return err
	}
	if workspace == nil {
		return errors.New("source loader returned a nil workspace")
	}
	defer func() {
		cleanupErr := workspace.Close()
		if runErr == nil && cleanupErr != nil {
			runErr = fmt.Errorf("cleanup source: %w", cleanupErr)
		}
	}()
	logger.Info("analyzing source", "package", *packagePattern)
	result, err := analyze.Run(analyze.Options{Source: workspace.Dir, Package: *packagePattern}, adv)
	if err != nil {
		return err
	}
	logger.Info("encoding VEX result")
	return vex.Encode(stdout, adv, result)
}

func parseLogLevel(value string) (slog.Level, error) {
	switch value {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("invalid --log-level %q: expected debug, info, warn, or error", value)
	}
}
