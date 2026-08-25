package dashboard

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/phantomgate/phantomgate/internal/store"
)

// ANSI color codes (Metasploit-style)
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
	colorBgRed   = "\033[41m"
	colorBgGreen = "\033[42m"
)

// Metasploit-style banner
const banner = `
%s    ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
   ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
   ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
   ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
   ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝%s
              %s██████╗  █████╗ ████████╗███████╗%s
             %s██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝%s
             %s██║  ███╗███████║   ██║   █████╗  %s
             %s██║   ██║██╔══██║   ██║   ██╔══╝  %s
             %s╚██████╔╝██║  ██║   ██║   ███████╗%s
              %s╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝%s

   %s─────────────────────────────────────────────────────────
     AiTM Reverse Proxy Framework for Red Teams
     Version: %s%s%s | Strict Terminal Mode
   %s─────────────────────────────────────────────────────────%s
`

// Dynamic status bar template
const statusBar = "\r  %s[%s]%s %s│ %sVictims:%s %d │ %sCreds:%s %d │ %sSessions:%s %d │ %sUptime:%s %s"

// Event prefixes
const (
	prefixInfo    = "[*]"
	prefixSuccess = "[+]"
	prefixWarning = "[!]"
	prefixError   = "[x]"
	prefixCapture = "[>]"
	prefixSession = "[$]"
	prefixLure    = "[~]"
	prefixARP     = "[*]"
	prefixDNS     = "[*]"
	prefixCA      = "[*]"
)

// Server is the terminal-based operator console
type Server struct {
	store     *store.Store
	adminPass string
	mu        sync.Mutex
	startTime time.Time
	victimCount    int64
	credCount      int64
	sessionCount   int64
}

// NewServer creates a new terminal console
func NewServer(s *store.Store, adminPass string) *Server {
	srv := &Server{
		store:     s,
		adminPass: adminPass,
		startTime: time.Now(),
	}
	go srv.eventLoop()
	return srv
}

// eventLoop listens for store events and prints them to terminal
func (s *Server) eventLoop() {
	for {
		select {
		case cred := <-s.store.OnCredential:
			s.printCredentialCapture(cred)
		case sess := <-s.store.OnSession:
			s.printSessionCapture(sess)
		case victim := <-s.store.OnNewVictim:
			s.printNewVictim(victim)
		}
	}
}

// Start begins the terminal console (no-op, events are async)
func (s *Server) Start(addr string) error {
	// Terminal console doesn't listen on HTTP
	// All output goes to stdout via event loop
	return nil
}

// PrintBanner displays the Metasploit-style animated banner
func (s *Server) PrintBanner(version string) {
	// Clear screen
	fmt.Print("\033[2J\033[H")

	// Print animated banner
	PrintBannerAnimated(version)
}

// PrintStatus displays the status bar
func (s *Server) PrintStatus() {
	stats := s.store.GetStats()
	victims := stats["total_victims"].(int)
	creds := stats["total_credentials"].(int)
	sessions := stats["total_sessions"].(int)
	uptime := time.Since(s.startTime).Truncate(time.Second)

	status := fmt.Sprintf(statusBar,
		colorDim, time.Now().Format("15:04:05"), colorReset,
		colorBold,
		colorCyan, colorReset, victims,
		colorYellow, colorReset, creds,
		colorGreen, colorReset, sessions,
		colorMagenta, colorReset, uptime.String(),
	)
	fmt.Print(status)
}

// printCredentialCapture prints a credential capture event
func (s *Server) printCredentialCapture(cred store.CapturedCredential) {
	s.mu.Lock()
	defer s.mu.Unlock()

	fmt.Printf("\n")
	fmt.Printf("  %s%sCREDENTIAL CAPTURED%s\n", colorRed, colorBold, colorReset)
	fmt.Printf("  %s────────────────────────────────────────────%s\n", colorDim, colorReset)
	fmt.Printf("  %sVictim:%s    %s%s%s\n", colorBold, colorReset, colorCyan, cred.VictimID[:8], colorReset)
	fmt.Printf("  %sUsername:%s  %s%s%s\n", colorBold, colorReset, colorYellow, cred.Username, colorReset)
	fmt.Printf("  %sPassword:%s  %s%s%s\n", colorBold, colorReset, colorRed, maskString(cred.Password), colorReset)
	fmt.Printf("  %sSource IP:%s %s%s%s\n", colorBold, colorReset, colorWhite, cred.SourceIP, colorReset)
	fmt.Printf("  %sPhishlet:%s  %s%s%s\n", colorBold, colorReset, colorMagenta, cred.Phishlet, colorReset)
	fmt.Printf("  %sTime:%s     %s%s%s\n", colorBold, colorReset, colorDim, cred.Timestamp.Format("15:04:05"), colorReset)
	fmt.Printf("  %s────────────────────────────────────────────%s\n", colorDim, colorReset)
	s.PrintStatus()
}

// printSessionCapture prints a session capture event
func (s *Server) printSessionCapture(sess store.CapturedSession) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tokenNames := make([]string, 0, len(sess.Cookies))
	for k := range sess.Cookies {
		tokenNames = append(tokenNames, k)
	}

	fmt.Printf("\n")
	fmt.Printf("  %s%sSESSION CAPTURED%s\n", colorGreen, colorBold, colorReset)
	fmt.Printf("  %s────────────────────────────────────────────%s\n", colorDim, colorReset)
	fmt.Printf("  %sVictim:%s    %s%s%s\n", colorBold, colorReset, colorCyan, sess.VictimID[:8], colorReset)
	fmt.Printf("  %sTokens:%s    %s%s%s\n", colorBold, colorReset, colorGreen, strings.Join(tokenNames, ", "), colorReset)
	fmt.Printf("  %sPhishlet:%s  %s%s%s\n", colorBold, colorReset, colorMagenta, sess.Phishlet, colorReset)
	fmt.Printf("  %sValid:%s     %s%v%s\n", colorBold, colorReset, colorGreen, sess.IsValid, colorReset)
	fmt.Printf("  %sTime:%s     %s%s%s\n", colorBold, colorReset, colorDim, sess.Timestamp.Format("15:04:05"), colorReset)
	fmt.Printf("  %s────────────────────────────────────────────%s\n", colorDim, colorReset)
	s.PrintStatus()
}

// printNewVictim prints a new victim event
func (s *Server) printNewVictim(victim store.Victim) {
	s.mu.Lock()
	defer s.mu.Unlock()

	fmt.Printf("\n")
	fmt.Printf("  %s%sNEW VICTIM%s %s%s%s\n", colorBlue, colorBold, colorReset, colorCyan, victim.ID[:8], colorReset)
	fmt.Printf("  %s────────────────────────────────────────────%s\n", colorDim, colorReset)
	fmt.Printf("  %sIP:%s        %s%s%s\n", colorBold, colorReset, colorWhite, victim.IP, colorReset)
	fmt.Printf("  %sUser-Agent:%s %s%s%s\n", colorBold, colorReset, colorDim, truncate(victim.UserAgent, 50), colorReset)
	fmt.Printf("  %sPhishlet:%s  %s%s%s\n", colorBold, colorReset, colorMagenta, victim.Phishlet, colorReset)
	fmt.Printf("  %s────────────────────────────────────────────%s\n", colorDim, colorReset)
	s.PrintStatus()
}

// PrintInfo prints an info message
func PrintInfo(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("  %s%s%s %s\n", colorCyan, prefixInfo, colorReset, msg)
}

// PrintSuccess prints a success message
func PrintSuccess(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("  %s%s%s %s\n", colorGreen, prefixSuccess, colorReset, msg)
}

// PrintWarning prints a warning message
func PrintWarning(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("  %s%s%s %s\n", colorYellow, prefixWarning, colorReset, msg)
}

// PrintError prints an error message
func PrintError(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("  %s%s%s %s\n", colorRed, prefixError, colorReset, msg)
}

// PrintSection prints a section header
func PrintSection(title string) {
	fmt.Printf("\n  %s%s%s\n", colorBold, title, colorReset)
	fmt.Printf("  %s%s%s\n", colorDim, strings.Repeat("─", 50), colorReset)
}

// PrintTable prints a formatted table row
func PrintTable(headers []string, rows [][]string) {
	// Print headers
	fmt.Printf("  ")
	for i, h := range headers {
		fmt.Printf("%s%-20s%s", colorBold, h, colorReset)
		if i < len(headers)-1 {
			fmt.Printf(" ")
		}
	}
	fmt.Println()

	// Print separator
	fmt.Printf("  ")
	for i := range headers {
		fmt.Printf("%s%s%s", colorDim, strings.Repeat("─", 20), colorReset)
		if i < len(headers)-1 {
			fmt.Printf(" ")
		}
	}
	fmt.Println()

	// Print rows
	for _, row := range rows {
		fmt.Printf("  ")
		for i, cell := range row {
			fmt.Printf("%-20s", cell)
			if i < len(row)-1 {
				fmt.Printf(" ")
			}
		}
		fmt.Println()
	}
}

// PrintSpinner prints an animated spinner
func PrintSpinner(message string, done chan bool) {
	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	i := 0
	for {
		select {
		case <-done:
			fmt.Printf("\r  %s%s%s %s\n", colorGreen, "✓", colorReset, message)
			return
		default:
			fmt.Printf("\r  %s%s%s %s", colorCyan, frames[i%len(frames)], colorReset, message)
			time.Sleep(100 * time.Millisecond)
			i++
		}
	}
}

// PrintProgressBar prints a progress bar
func PrintProgressBar(label string, current, total int) {
	width := 30
	percent := float64(current) / float64(total)
	filled := int(float64(width) * percent)

	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	fmt.Printf("\r  %s%s%s [%s] %d%%", colorCyan, label, colorReset, bar, int(percent*100))

	if current >= total {
		fmt.Println()
	}
}

// PrintBannerAnimated prints the banner with typing effect
func PrintBannerAnimated(version string) {
	fmt.Print("\033[2J\033[H")

	ascii := []string{
		"    ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗",
		"    ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║",
		"    ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║",
		"    ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║",
		"    ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║",
		"    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝",
	}

	// Print ASCII art with color animation
	for _, line := range ascii {
		for _, ch := range line {
			if ch == '█' || ch == '╗' || ch == '╚' || ch == '╝' || ch == '║' {
				fmt.Printf("%s%s%s", colorRed, string(ch), colorReset)
			} else {
				fmt.Print(string(ch))
			}
			time.Sleep(5 * time.Millisecond)
		}
		fmt.Println()
	}

	// Print subtitle
	subtitle := []string{
		"               ███████╗███████╗███████╗██████╗ ███████╗",
		"               ██╔════╝██╔════╝██╔════╝██╔══██╗██╔════╝",
		"               █████╗  █████╗  █████╗  ██████╔╝█████╗  ",
		"               ██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗██╔══╝  ",
		"               ██║     ███████╗███████╗██║  ██║███████╗",
		"               ╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝",
	}

	for _, line := range subtitle {
		for _, ch := range line {
			if ch == '█' || ch == '╗' || ch == '╚' || ch == '╝' || ch == '║' {
				fmt.Printf("%s%s%s", colorRed, string(ch), colorReset)
			} else {
				fmt.Print(string(ch))
			}
			time.Sleep(3 * time.Millisecond)
		}
		fmt.Println()
	}

	fmt.Println()
	fmt.Printf("   %s─────────────────────────────────────────────────────────%s\n", colorDim, colorReset)
	fmt.Printf("     %sAiTM Reverse Proxy Framework for Red Teams%s\n", colorWhite, colorReset)
	fmt.Printf("     %sVersion: %s%s%s | Strict Terminal Mode%s\n", colorDim, colorBold, version, colorDim, colorReset)
	fmt.Printf("   %s─────────────────────────────────────────────────────────%s\n", colorDim, colorReset)
	fmt.Println()
}

func maskString(s string) string {
	if len(s) <= 4 {
		return strings.Repeat("*", len(s))
	}
	return s[:2] + strings.Repeat("*", len(s)-4) + s[len(s)-2:]
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max-3] + "..."
	}
	return s
}

// Stats returns current stats for external use
func (s *Server) Stats() map[string]interface{} {
	return s.store.GetStats()
}
