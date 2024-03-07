package cmd

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/lytics/logrus"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/motemen/go-loghttp"
	"github.com/omniboost/oauth-proxy/db"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:              "cmd",
	Short:            "Oauth proxy to allow multiple clients to use the same token",
	Long:             `Oauth proxy to allow multiple clients to use the same token`,
	TraverseChildren: true,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) {
	// 	log.Println(cmd, args)
	// 	serverCmd.Run(cmd, args)
	// },
	RunE: func(cmd *cobra.Command, args []string) error {
		// @TODO: this doesn't parse subcmd flags
		return serverCmd.Execute()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	// Flush buffered events before the program terminates.
	defer sentry.Flush(2 * time.Second)

	if err := rootCmd.Execute(); err != nil {
		sentry.CaptureException(err)
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.cmd.yaml)")

	rootCmd.PersistentFlags().CountP("verbose", "v", "Verbosity (repeat for more verbose)")

	cobra.OnInitialize(initLogger, initSentry)

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	// rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	viper.BindPFlags(pflag.CommandLine)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".cmd" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".cmd")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}

func initLogger() {
	verbosity, err := rootCmd.PersistentFlags().GetCount("verbose")
	if err != nil {
		logErrorAndExit(err)
	}

	if verbosity == 0 {
		logrus.SetLevel(logrus.ErrorLevel)
	} else if verbosity == 1 {
		logrus.SetLevel(logrus.WarnLevel)
	} else if verbosity == 2 {
		logrus.SetLevel(logrus.InfoLevel)
	} else {
		logrus.SetLevel(logrus.DebugLevel)
	}

	if verbosity > 2 {
		// log http outgoing requests + responses
		http.DefaultTransport = loghttp.DefaultTransport
		loghttp.DefaultTransport.LogRequest = func(req *http.Request) {
			b, _ := httputil.DumpRequestOut(req, true)
			logrus.Debug("Client outgoing request:")
			for _, s := range strings.Split(string(b), "\r\n") {
				logrus.Debug(s)
			}
		}
		loghttp.DefaultTransport.LogResponse = func(res *http.Response) {
			b, _ := httputil.DumpResponse(res, true)
			logrus.Debug("Client incoming response:")
			for _, s := range strings.Split(string(b), "\r\n") {
				logrus.Debug(s)
			}
		}
	}

	// Init logging of queries
	db.XOLog = func(s string, p ...interface{}) {
		logrus.Debug("> SQL: %s -- params: %v\n", s, p)
	}
}

func initSentry() {
	dsn := os.Getenv("SENTRY_DSN")
	if dsn == "" {
		return
	}

	sentry.Init(sentry.ClientOptions{
		Dsn: dsn,
	})
}

func logErrorAndExit(err error) {
	logrus.Error(err)
	os.Exit(1)
}
