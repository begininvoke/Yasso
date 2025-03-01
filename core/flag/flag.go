package flag

import (
	"Yasso/core/logger"
	"Yasso/core/plugin"
	"Yasso/pkg/exploit"
	"os"
	"time"

	"github.com/spf13/cobra"
)

type allFlags struct {
	Hosts     string // Global variable: identifies IP list or file path
	Ports     string // Global variable: identifies ports to scan
	Timeout   int    // Global variable: identifies timeout duration
	NoCrack   bool   // Global variable: identifies whether to enable brute force in all module
	NoAlive   bool   // Global variable: whether to use ping to determine live hosts
	User      string // Global variable: identifies username dictionary for all module brute force
	Pass      string // Global variable: identifies password dictionary for all module brute force
	Thread    int    // Global variable: identifies thread count for all module scanning
	NoService bool   // Global variable: identifies whether to detect services in all module
	NoVulcan  bool   // Global variable: identifies whether to perform host-level vulnerability scanning in all module
}

type BurpFlags struct {
	Hosts   string // Global variable: identifies IP list or file path
	Method  string // Service name to brute force
	User    string // Username dictionary used for brute force
	Pass    string // Password dictionary used for brute force
	Thread  int    // Thread count used for brute force
	Timeout int    // Timeout for brute force
	IsAlive bool   // Whether to check if host is alive before brute force
}

var burp BurpFlags
var all allFlags

var rootCmd = &cobra.Command{
	Use:   "Yasso",
	Short: "\n_____.___.                         ____  ___\n\\__  |   |____    ______ __________\\   \\/  /\n /   |   \\__  \\  /  ___//  ___/  _ \\\\     / \n \\____   |/ __ \\_\\___ \\ \\___ (  <_> )     \\ \n / ______(____  /____  >____  >____/___/\\  \\\n \\/           \\/     \\/     \\/           \\_/\n",
}

var allCmd = &cobra.Command{
	Use:   "all",
	Short: "Use all scanner module (.attention) Traffic is very big",
	Run: func(cmd *cobra.Command, args []string) {
		if all.Hosts == "" {
			_ = cmd.Help()
			return
		}
		scanner := plugin.NewAllScanner(all.Hosts, all.Ports, all.NoAlive, all.NoCrack, all.User, all.Pass, all.Thread, time.Duration(all.Timeout)*1000*time.Millisecond, all.NoService, all.NoVulcan)
		scanner.RunEnumeration()
	},
}

var serviceCmd = &cobra.Command{
	Use:   "service",
	Short: "Detection or blasting services by module",
	Run: func(cmd *cobra.Command, args []string) {
		if burp.Hosts == "" {
			_ = cmd.Help()
			return
		}
		plugin.BruteService(burp.User, burp.Pass, burp.Hosts, burp.Method, burp.Thread, time.Duration(burp.Timeout)*1000*time.Millisecond, burp.IsAlive)
	},
}

var ExpCmd = &cobra.Command{
	Use:   "exploit",
	Short: "Exploits to attack the service",
	Run: func(cmd *cobra.Command, args []string) {
		if cmd.HasSubCommands() {
			_ = cmd.Help()
		}
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&logger.LogFile, "output", "result.txt", "set logger file")
	allCmd.Flags().StringVar(&logger.LogJson, "json", "", "Set JSON format output file")
	allCmd.Flags().StringVarP(&all.Hosts, "hosts", "H", "", "Set scan target parameters (.eg) \n[192.168.248.1/24]\n[192.168.248.1-255]\n[example.txt]")
	allCmd.Flags().StringVar(&all.Ports, "ports", "", "Set port parameters for scanning (.eg) null will use default port number top 1000")
	allCmd.Flags().IntVar(&all.Timeout, "timeout", 1, "Set scan timeout, default 1 second")
	allCmd.Flags().BoolVar(&all.NoCrack, "no-crack", false, "Set whether to brute force vulnerable services during scanning")
	allCmd.Flags().BoolVar(&all.NoAlive, "no-alive", false, "Set whether to first detect if host is alive during scanning")
	allCmd.Flags().StringVar(&all.User, "user-dic", "", "Set username dictionary used for brute force during scanning (.eg) null will use default username dictionary")
	allCmd.Flags().StringVar(&all.Pass, "pass-dic", "", "Set password dictionary used for brute force during scanning (.eg) null will use default password dictionary")
	allCmd.Flags().IntVar(&all.Thread, "thread", 500, "Set scanning thread count (.eg) default 500 threads")
	allCmd.Flags().BoolVar(&all.NoService, "no-service", false, "Set whether to detect services during scanning")
	allCmd.Flags().BoolVar(&all.NoVulcan, "no-vuln", false, "Set whether to detect host-level vulnerabilities during scanning")
	rootCmd.AddCommand(allCmd)
	serviceCmd.Flags().StringVarP(&burp.Hosts, "hosts", "H", "", "Set scan target parameters (.eg) \n[192.168.248.1/24]\n[192.168.248.1-255]\n[example.txt]")
	serviceCmd.Flags().StringVar(&burp.Method, "module", "", "Specify service name to brute force (.eg) \n[mssql,ftp,ssh,mysql,rdp,postgres,redis,winrm,smb,mongo]\nSeparated by commas, can brute force multiple services simultaneously (--module ssh:22,mysql:3306,rdp:3389)")
	serviceCmd.Flags().IntVar(&burp.Thread, "thread", 500, "Set scanning thread count (.eg) default 500 threads")
	serviceCmd.Flags().StringVar(&burp.User, "user-dic", "", "Set username dictionary used for brute force during scanning (.eg) null will use default username dictionary")
	serviceCmd.Flags().StringVar(&burp.Pass, "pass-dic", "", "Set password dictionary used for brute force during scanning (.eg) null will use default password dictionary")
	serviceCmd.Flags().IntVar(&burp.Timeout, "timeout", 1, "Set brute force timeout, default 1 second")
	serviceCmd.Flags().BoolVar(&burp.IsAlive, "is-alive", true, "Whether to perform ping detection for alive hosts before brute force")
	rootCmd.AddCommand(serviceCmd)
	rootCmd.AddCommand(ExpCmd)
	// Exploitation module commands
	ExpCmd.AddCommand(exploit.MssqlCmd)
	ExpCmd.AddCommand(exploit.SshCmd)
	ExpCmd.AddCommand(exploit.WinRmCmd)
	ExpCmd.AddCommand(exploit.RedisCmd)
	ExpCmd.AddCommand(exploit.SunLoginCmd)
	ExpCmd.AddCommand(exploit.LdapReaperCmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(0)
	}
}
