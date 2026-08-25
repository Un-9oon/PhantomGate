package arp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ══════════════════════════════════════════════════════════════════════════════
// PHANTOMGATE NOTIFICATIONS v3.0 — ALERT SYSTEM
// ══════════════════════════════════════════════════════════════════════════════

type Notifier struct {
	enabled   bool
	targets   []NotifyTarget
	queue     chan *Alert
	stopChan  chan struct{}
}

type NotifyTarget struct {
	Type    string // "telegram", "discord", "webhook"
	URL     string
	Token   string
	ChatID  string
}

type Alert struct {
	Type      string
	Title     string
	Message   string
	Severity  string
	Timestamp time.Time
}

type TelegramMessage struct {
	ChatID    string `json:"chat_id"`
	Text      string `json:"text"`
	ParseMode string `json:"parse_mode"`
}

type DiscordWebhook struct {
	Content string         `json:"content"`
	Embeds  []DiscordEmbed `json:"embeds,omitempty"`
}

type DiscordEmbed struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Color       int    `json:"color"`
}

func NewNotifier() *Notifier {
	return &Notifier{
		enabled:  false,
		targets:  make([]NotifyTarget, 0),
		queue:    make(chan *Alert, 100),
		stopChan: make(chan struct{}),
	}
}

func (n *Notifier) AddTarget(target NotifyTarget) {
	n.targets = append(n.targets, target)
	n.enabled = true
}

func (n *Notifier) Start() {
	go n.processLoop()
}

func (n *Notifier) Stop() {
	close(n.stopChan)
}

func (n *Notifier) processLoop() {
	for {
		select {
		case <-n.stopChan:
			return
		case alert := <-n.queue:
			n.sendAlert(alert)
		}
	}
}

func (n *Notifier) SendAlert(alertType, title, message, severity string) {
	if !n.enabled {
		return
	}

	alert := &Alert{
		Type:      alertType,
		Title:     title,
		Message:   message,
		Severity:  severity,
		Timestamp: time.Now(),
	}

	select {
	case n.queue <- alert:
	default:
		// Queue full, drop alert
	}
}

func (n *Notifier) sendAlert(alert *Alert) {
	for _, target := range n.targets {
		switch target.Type {
		case "telegram":
			n.sendTelegram(target, alert)
		case "discord":
			n.sendDiscord(target, alert)
		case "webhook":
			n.sendWebhook(target, alert)
		}
	}
}

func (n *Notifier) sendTelegram(target NotifyTarget, alert *Alert) {
	emoji := "ℹ️"
	switch alert.Severity {
	case "high":
		emoji = "🚨"
	case "medium":
		emoji = "⚠️"
	case "low":
		emoji = "ℹ️"
	}

	text := fmt.Sprintf("%s *%s*\n\n%s\n\n_Time: %s_",
		emoji,
		alert.Title,
		alert.Message,
		alert.Timestamp.Format("2006-01-02 15:04:05"))

	msg := TelegramMessage{
		ChatID:    target.ChatID,
		Text:      text,
		ParseMode: "Markdown",
	}

	data, _ := json.Marshal(msg)
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", target.Token)

	resp, err := http.Post(url, "application/json", strings.NewReader(string(data)))
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

func (n *Notifier) sendDiscord(target NotifyTarget, alert *Alert) {
	color := 0x00ff00
	switch alert.Severity {
	case "high":
		color = 0xff0000
	case "medium":
		color = 0xffff00
	case "low":
		color = 0x00ff00
	}

	webhook := DiscordWebhook{
		Content: fmt.Sprintf("**%s**\n%s", alert.Title, alert.Message),
		Embeds: []DiscordEmbed{
			{
				Title:       alert.Title,
				Description: alert.Message,
				Color:       color,
			},
		},
	}

	data, _ := json.Marshal(webhook)
	resp, err := http.Post(target.URL, "application/json", strings.NewReader(string(data)))
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

func (n *Notifier) sendWebhook(target NotifyTarget, alert *Alert) {
	payload := map[string]interface{}{
		"type":      alert.Type,
		"title":     alert.Title,
		"message":   alert.Message,
		"severity":  alert.Severity,
		"timestamp": alert.Timestamp.Format(time.RFC3339),
	}

	data, _ := json.Marshal(payload)
	resp, err := http.Post(target.URL, "application/json", strings.NewReader(string(data)))
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

// Alert types
const (
	AlertNewHost      = "new_host"
	AlertHostDown     = "host_down"
	AlertARPChange    = "arp_change"
	AlertCredential   = "credential"
	AlertSession      = "session"
	AlertSSLStrip     = "ssl_strip"
	AlertAttack       = "attack"
)

// Helper to create formatted alert messages
func FormatHostAlert(hostIP, hostMAC, vendor string) string {
	return fmt.Sprintf("New host discovered:\nIP: %s\nMAC: %s\nVendor: %s",
		hostIP, hostMAC, vendor)
}

func FormatCredentialAlert(username, service, sourceIP string) string {
	return fmt.Sprintf("Credential captured:\nUsername: %s\nService: %s\nSource: %s",
		username, service, sourceIP)
}

func FormatARPChangeAlert(ip, oldMAC, newMAC string) string {
	return fmt.Sprintf("ARP cache changed:\nIP: %s\nOld MAC: %s\nNew MAC: %s",
		ip, oldMAC, newMAC)
}
