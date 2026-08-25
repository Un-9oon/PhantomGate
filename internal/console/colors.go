package console

// ANSI color codes -- Metasploit-style scheme
const (
	colorReset   = "\033[0m"
	colorRed     = "\033[1;31m"
	colorGreen   = "\033[1;32m"
	colorYellow  = "\033[1;33m"
	colorBlue    = "\033[1;34m"
	colorMagenta = "\033[1;35m"
	colorCyan    = "\033[1;36m"
	colorWhite   = "\033[1;37m"
	colorDim     = "\033[2m"
	colorBold    = "\033[1m"
)

// Event prefixes matching Metasploit conventions
const (
	prefixInfo    = "[*]"
	prefixSuccess = "[+]"
	prefixWarning = "[!]"
	prefixError   = "[-]"
	prefixCapture = "[>]"
	prefixSession = "[$]"
	prefixLure    = "[~]"
)
