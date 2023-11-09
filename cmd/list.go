package main

import (
	"github.com/jmanero/vault-yubikey-helper/pkg/common"
	"github.com/spf13/cobra"
)

func init() {
	CLI.AddCommand(&cobra.Command{
		Use:   "ls",
		Short: "List available PIV devices/slots for init, unseal, and transfer operations",
		RunE:  List,
		Args:  cobra.NoArgs,
	})
}

// List PIV devices/slots
func List(cmd *cobra.Command, args []string) (err error) {
	cards, err := common.ScanCards()

	for i, card := range cards {
		cmd.Printf("%d: %s\n", i, card)
	}

	if err != nil {
		cmd.PrintErrln(err)
	}

	return nil
}
