package cmd

import (
	"log"

	oauthproxy "github.com/omniboost/oauth-proxy"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Starts up the proxy server",
	Long:  ``,
	RunE: func(cmd *cobra.Command, args []string) error {
		err := viper.BindPFlags(cmd.Flags())
		if err != nil {
			log.Fatal(err)
			return err
		}

		s, err := oauthproxy.NewServer()
		if err != nil {
			log.Fatal(err)
			return err
		}

		port := viper.GetInt("port")
		s.SetPort(port)
		err = s.Start()
		log.Fatal(err)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// serverCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// serverCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	serverCmd.Flags().IntP("port", "p", 8080, "Port to run the proxy server on")
}
