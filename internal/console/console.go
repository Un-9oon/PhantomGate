package console

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/chzyer/readline"
	"github.com/phantomgate/phantomgate/internal/config"
	"github.com/phantomgate/phantomgate/internal/lure"
	"github.com/phantomgate/phantomgate/internal/phishlet"
	"github.com/phantomgate/phantomgate/internal/proxy"
	"github.com/phantomgate/phantomgate/internal/store"
)

// Console is the interactive Metasploit-style operator console
type Console struct {
	readline        *readline.Instance
	config          *config.Config
	currentPhishlet *phishlet.Phishlet
	phishletMgr     *phishlet.PhishletManager
	store           *store.Store
	lureGen         *lure.Generator
	proxyEngine     *proxy.PhantomProxy
	proxyRunning    bool
	startTime       time.Time
	colorEnabled    bool
	spoolFile       *os.File
}

// NewConsole creates a new interactive console
func NewConsole(pm *phishlet.PhishletManager, s *store.Store) (*Console, error) {
	rl, err := readline.New("pg > ")
	if err != nil {
		return nil, fmt.Errorf("failed to initialize readline: %w", err)
	}

	return &Console{
		readline:     rl,
		config:       config.DefaultConfig(),
		phishletMgr:  pm,
		store:        s,
		lureGen:      lure.NewGenerator(""),
		startTime:    time.Now(),
		colorEnabled: true,
	}, nil
}

// Run starts the interactive console loop
func (c *Console) Run() {
	c.printBanner()
	c.setupCompleter()

	for {
		c.updatePrompt()

		line, err := c.readline.Readline()
		if err == readline.ErrInterrupt {
			continue
		} else if err == io.EOF {
			break
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Handle spool
		if c.spoolFile != nil {
			fmt.Fprintf(c.spoolFile, "%s\n", line)
		}

		parts := c.parseLine(line)
		if len(parts) == 0 {
			continue
		}

		cmd := strings.ToLower(parts[0])
		args := parts[1:]

		c.dispatch(cmd, args)
	}
}

// parseLine splits a command line into parts, handling quotes
func (c *Console) parseLine(line string) []string {
	var parts []string
	var current strings.Builder
	inQuote := false
	quoteChar := byte(0)

	for i := 0; i < len(line); i++ {
		ch := line[i]

		if inQuote {
			if ch == quoteChar {
				inQuote = false
			} else {
				current.WriteByte(ch)
			}
		} else if ch == '"' || ch == '\'' {
			inQuote = true
			quoteChar = ch
		} else if ch == ' ' || ch == '\t' {
			if current.Len() > 0 {
				parts = append(parts, current.String())
				current.Reset()
			}
		} else {
			current.WriteByte(ch)
		}
	}

	if current.Len() > 0 {
		parts = append(parts, current.String())
	}

	return parts
}

// updatePrompt changes the prompt based on current context
func (c *Console) updatePrompt() {
	if c.currentPhishlet != nil {
		c.readline.SetPrompt(fmt.Sprintf(
			"%s pg %s(%s)%s > ",
			colorCyan, colorReset, c.currentPhishlet.Name, colorCyan,
		))
	} else {
		c.readline.SetPrompt("pg > ")
	}
}

// Stop cleans up the console
func (c *Console) Stop() {
	if c.spoolFile != nil {
		c.spoolFile.Close()
	}
	c.readline.Close()
}
