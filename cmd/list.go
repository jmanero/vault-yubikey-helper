package main

import (
	"github.com/jmanero/vault-yubikey-helper/cmd/util"
	"github.com/jmanero/vault-yubikey-helper/pkg/piv"
	"github.com/spf13/cobra"
	"pault.ag/go/ykpiv"
)

func init() {
	CLI.AddCommand(&cobra.Command{
		Use:   "ls",
		Short: "List available PIV devices/slots for init, unseal, share, and pki operations",
		RunE:  List,
		Args:  cobra.NoArgs,
	})
}

// List PIV devices/slots
func List(cmd *cobra.Command, args []string) (err error) {
	cards, selected, err := piv.Scan(util.Yubikey.WithSlot(ykpiv.KeyManagement))

	if err != nil {
		cmd.PrintErrln(err)
	}

	if !selected {
		cmd.PrintErrln("!! No cards match the given --serial/--avoid-serial flags")
	}

	for i, card := range cards {
		cmd.Printf("%d: %s\n", i, card)
	}

	return nil
}
