package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/PeculiarVentures/scp/transport/pcsc"
)

// cmdReaders prints the list of PC/SC readers visible to the OS.
//
// This is the one subcommand that does not go through env.connect —
// it is precisely "what's the OS-level state of PC/SC right now,"
// and indirecting through a connector that returns a Transport
// would lose the answer to that question. Tests cover the rest of
// the CLI, not this command.
func cmdReaders(_ context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("readers", env)
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}

	readers, err := pcsc.ListReaders()
	if err != nil {
		return fmt.Errorf("list readers: %w", err)
	}

	if *jsonMode {
		out := struct {
			Readers []string `json:"readers"`
		}{Readers: readers}
		enc := json.NewEncoder(env.out)
		enc.SetIndent("", "  ")
		return enc.Encode(&out)
	}

	if len(readers) == 0 {
		fmt.Fprintln(env.out, "no readers connected")
		return nil
	}
	for _, r := range readers {
		fmt.Fprintln(env.out, r)
	}
	return nil
}
