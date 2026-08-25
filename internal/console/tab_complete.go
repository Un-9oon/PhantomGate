package console

import (
	"github.com/chzyer/readline"
)

// setupCompleter configures tab completion for the console
func (c *Console) setupCompleter() {
	c.readline.Config.AutoComplete = readline.NewPrefixCompleter(
		// Module selection
		readline.PcItem("use"),
		readline.PcItem("back"),
		readline.PcItem("search"),
		readline.PcItem("info"),

		// Options
		readline.PcItem("show",
			readline.PcItem("options"),
			readline.PcItem("lures"),
			readline.PcItem("targets"),
			readline.PcItem("advanced"),
			readline.PcItem("phishlets"),
			readline.PcItem("stats"),
		),
		readline.PcItem("set",
			readline.PcItem("domain"),
			readline.PcItem("listen"),
			readline.PcItem("https-port"),
			readline.PcItem("http-port"),
			readline.PcItem("admin-port"),
			readline.PcItem("admin-pass"),
			readline.PcItem("tls-mode"),
			readline.PcItem("cert"),
			readline.PcItem("key"),
		),
		readline.PcItem("unset",
			readline.PcItem("domain"),
			readline.PcItem("listen"),
			readline.PcItem("cert"),
			readline.PcItem("key"),
		),

		// Execution
		readline.PcItem("run"),
		readline.PcItem("exploit"),
		readline.PcItem("start"),
		readline.PcItem("stop"),
		readline.PcItem("check"),

		// Lures
		readline.PcItem("lure",
			readline.PcItem("create"),
			readline.PcItem("list"),
			readline.PcItem("delete"),
			readline.PcItem("show"),
		),

		// Network
		readline.PcItem("dns",
			readline.PcItem("start"),
			readline.PcItem("stop"),
			readline.PcItem("add"),
			readline.PcItem("remove"),
			readline.PcItem("stats"),
		),
		readline.PcItem("arp",
			readline.PcItem("start"),
			readline.PcItem("stop"),
			readline.PcItem("scan"),
		),

		// Data
		readline.PcItem("sessions"),
		readline.PcItem("creds"),
		readline.PcItem("victims"),
		readline.PcItem("stats"),

		// System
		readline.PcItem("help"),
		readline.PcItem("banner"),
		readline.PcItem("version"),
		readline.PcItem("color",
			readline.PcItem("on"),
			readline.PcItem("off"),
		),
		readline.PcItem("resource"),
		readline.PcItem("spool"),
		readline.PcItem("exit"),
		readline.PcItem("quit"),
	)
}
