package injection

import (
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ══════════════════════════════════════════════════════════════════════════════
// PHANTOMGATE INJECTION ENGINE v3.0 — CHARACTER-BY-CHARACTER INJECTION
// ══════════════════════════════════════════════════════════════════════════════

type InjectionEngine struct {
	iface       string
	fd          int
	running     bool
	stopChan    chan struct{}
	
	// Targets
	targets     map[string]*InjectionTarget
	targetsMu   sync.RWMutex
	
	// Queues
	queue       chan *InjectionTask
	priority    chan *InjectionTask
	
	// Statistics
	stats       *InjectionStats
	
	// Configuration
	config      *InjectionConfig
}

type InjectionTarget struct {
	ID          string
	IP          net.IP
	MAC         net.HardwareAddr
	Port        uint16
	Protocol    string
	Active      bool
	LastAttack  time.Time
	SuccessRate float64
}

type InjectionTask struct {
	ID          string
	TargetID    string
	Payload     []byte
	Type        InjectionType
	Priority    int
	Delay       time.Duration
	Callback    func(bool)
	RetryCount  int
	MaxRetries  int
}

type InjectionType int

const (
	InjectionTypeChar InjectionType = iota
	InjectionTypeString
	InjectionTypePayload
	InjectionTypeCommand
	InjectionTypeScript
)

type InjectionStats struct {
	TasksQueued    int64
	TasksSent      int64
	TasksSuccess   int64
	TasksFailed    int64
	CharsSent      int64
	StartTime      time.Time
}

type InjectionConfig struct {
	Interface     string
	QueueSize     int
	MaxRetries    int
	Delay         time.Duration
	CharDelay     time.Duration
	BurstMode     bool
	BurstSize     int
	BurstDelay    time.Duration
}

func NewInjectionEngine(cfg InjectionConfig) *InjectionEngine {
	if cfg.QueueSize == 0 {
		cfg.QueueSize = 1000
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 3
	}
	if cfg.Delay == 0 {
		cfg.Delay = 10 * time.Millisecond
	}
	if cfg.CharDelay == 0 {
		cfg.CharDelay = 50 * time.Millisecond
	}
	if cfg.BurstSize == 0 {
		cfg.BurstSize = 10
	}
	if cfg.BurstDelay == 0 {
		cfg.BurstDelay = 100 * time.Millisecond
	}
	
	return &InjectionEngine{
		iface:     cfg.Interface,
		stopChan:  make(chan struct{}),
		targets:   make(map[string]*InjectionTarget),
		queue:     make(chan *InjectionTask, cfg.QueueSize),
		priority:  make(chan *InjectionTask, 100),
		config:    &cfg,
		stats: &InjectionStats{
			StartTime: time.Now(),
		},
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// CORE FUNCTIONS
// ══════════════════════════════════════════════════════════════════════════════

func (e *InjectionEngine) Start() error {
	e.running = true
	
	log.Printf("[INJECT] Starting injection engine on %s", e.iface)
	log.Printf("[INJECT] Queue size: %d | Max retries: %d", e.config.QueueSize, e.config.MaxRetries)
	
	// Start processors
	go e.processQueue()
	go e.processPriority()
	
	return nil
}

func (e *InjectionEngine) Stop() {
	e.running = false
	close(e.stopChan)
	
	e.printStats()
	log.Printf("[INJECT] Injection engine stopped")
}

// ══════════════════════════════════════════════════════════════════════════════
// TARGET MANAGEMENT
// ══════════════════════════════════════════════════════════════════════════════

func (e *InjectionEngine) AddTarget(target *InjectionTarget) {
	e.targetsMu.Lock()
	defer e.targetsMu.Unlock()
	
	e.targets[target.ID] = target
	log.Printf("[INJECT] Added target: %s (%s)", target.ID, target.IP)
}

func (e *InjectionEngine) RemoveTarget(targetID string) {
	e.targetsMu.Lock()
	defer e.targetsMu.Unlock()
	
	delete(e.targets, targetID)
}

func (e *InjectionEngine) GetTarget(targetID string) *InjectionTarget {
	e.targetsMu.RLock()
	defer e.targetsMu.RUnlock()
	
	return e.targets[targetID]
}

// ══════════════════════════════════════════════════════════════════════════════
// INJECTION METHODS
// ══════════════════════════════════════════════════════════════════════════════

func (e *InjectionEngine) InjectChar(targetID string, char byte) error {
	task := &InjectionTask{
		ID:       generateID(),
		TargetID: targetID,
		Payload:  []byte{char},
		Type:     InjectionTypeChar,
		Priority: 0,
		Delay:    e.config.CharDelay,
	}
	
	return e.enqueueTask(task)
}

func (e *InjectionEngine) InjectString(targetID string, str string) error {
	// Inject character by character
	for i := 0; i < len(str); i++ {
		err := e.InjectChar(targetID, str[i])
		if err != nil {
			return err
		}
		time.Sleep(e.config.CharDelay)
	}
	return nil
}

func (e *InjectionEngine) InjectPayload(targetID string, payload []byte) error {
	task := &InjectionTask{
		ID:       generateID(),
		TargetID: targetID,
		Payload:  payload,
		Type:     InjectionTypePayload,
		Priority: 1,
		Delay:    e.config.Delay,
	}
	
	return e.enqueueTask(task)
}

func (e *InjectionEngine) InjectCommand(targetID string, cmd string) error {
	task := &InjectionTask{
		ID:       generateID(),
		TargetID: targetID,
		Payload:  []byte(cmd),
		Type:     InjectionTypeCommand,
		Priority: 2,
		Delay:    e.config.Delay,
	}
	
	return e.enqueueTask(task)
}

func (e *InjectionEngine) InjectScript(targetID string, script []string) error {
	// Convert script to payload
	payload := []byte{}
	for _, line := range script {
		payload = append(payload, []byte(line+"\n")...)
	}
	
	task := &InjectionTask{
		ID:       generateID(),
		TargetID: targetID,
		Payload:  payload,
		Type:     InjectionTypeScript,
		Priority: 3,
		Delay:    e.config.Delay,
	}
	
	return e.enqueueTask(task)
}

func (e *InjectionEngine) InjectPriority(targetID string, payload []byte) error {
	task := &InjectionTask{
		ID:       generateID(),
		TargetID: targetID,
		Payload:  payload,
		Type:     InjectionTypePayload,
		Priority: 10, // High priority
		Delay:    0,
	}
	
	select {
	case e.priority <- task:
		atomic.AddInt64(&e.stats.TasksQueued, 1)
		return nil
	default:
		return ErrQueueFull
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// QUEUE PROCESSORS
// ══════════════════════════════════════════════════════════════════════════════

func (e *InjectionEngine) processQueue() {
	for {
		select {
		case <-e.stopChan:
			return
		case task := <-e.queue:
			e.executeTask(task)
		}
	}
}

func (e *InjectionEngine) processPriority() {
	for {
		select {
		case <-e.stopChan:
			return
		case task := <-e.priority:
			e.executeTask(task)
		}
	}
}

func (e *InjectionEngine) executeTask(task *InjectionTask) {
	atomic.AddInt64(&e.stats.TasksSent, 1)
	
	target := e.GetTarget(task.TargetID)
	if target == nil {
		atomic.AddInt64(&e.stats.TasksFailed, 1)
		return
	}
	
	log.Printf("[INJECT] Executing task %s on %s (%d bytes)", task.ID, task.TargetID, len(task.Payload))
	
	// Execute based on type
	var success bool
	switch task.Type {
	case InjectionTypeChar:
		success = e.sendChar(target, task.Payload[0])
	case InjectionTypeString:
		success = e.sendString(target, string(task.Payload))
	case InjectionTypePayload:
		success = e.sendPayload(target, task.Payload)
	case InjectionTypeCommand:
		success = e.sendCommand(target, string(task.Payload))
	case InjectionTypeScript:
		success = e.sendScript(target, string(task.Payload))
	}
	
	if success {
		atomic.AddInt64(&e.stats.TasksSuccess, 1)
		target.LastAttack = time.Now()
	} else {
		// Retry if needed
		if task.RetryCount < task.MaxRetries {
			task.RetryCount++
			e.queue <- task
		} else {
			atomic.AddInt64(&e.stats.TasksFailed, 1)
		}
	}
	
	// Call callback if set
	if task.Callback != nil {
		task.Callback(success)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// SEND METHODS
// ══════════════════════════════════════════════════════════════════════════════

func (e *InjectionEngine) sendChar(target *InjectionTarget, char byte) bool {
	// Send single character
	atomic.AddInt64(&e.stats.CharsSent, 1)
	return true
}

func (e *InjectionEngine) sendString(target *InjectionTarget, str string) bool {
	for i := 0; i < len(str); i++ {
		if !e.sendChar(target, str[i]) {
			return false
		}
		time.Sleep(e.config.CharDelay)
	}
	return true
}

func (e *InjectionEngine) sendPayload(target *InjectionTarget, payload []byte) bool {
	// Send full payload
	return true
}

func (e *InjectionEngine) sendCommand(target *InjectionTarget, cmd string) bool {
	// Send command
	return true
}

func (e *InjectionEngine) sendScript(target *InjectionTarget, script string) bool {
	// Send script line by line
	lines := splitLines(script)
	for _, line := range lines {
		if !e.sendString(target, line+"\n") {
			return false
		}
		time.Sleep(e.config.Delay)
	}
	return true
}

// ══════════════════════════════════════════════════════════════════════════════
// BURST MODE
// ══════════════════════════════════════════════════════════════════════════════

func (e *InjectionEngine) BurstInject(targetID string, payloads [][]byte) error {
	if !e.config.BurstMode {
		// Fall back to normal injection
		for _, payload := range payloads {
			err := e.InjectPayload(targetID, payload)
			if err != nil {
				return err
			}
		}
		return nil
	}
	
	// Burst mode: send multiple payloads quickly
	for i := 0; i < len(payloads); i += e.config.BurstSize {
		end := i + e.config.BurstSize
		if end > len(payloads) {
			end = len(payloads)
		}
		
		batch := payloads[i:end]
		for _, payload := range batch {
			e.InjectPayload(targetID, payload)
		}
		
		time.Sleep(e.config.BurstDelay)
	}
	
	return nil
}

// ══════════════════════════════════════════════════════════════════════════════
// UTILITY
// ══════════════════════════════════════════════════════════════════════════════

func (e *InjectionEngine) enqueueTask(task *InjectionTask) error {
	select {
	case e.queue <- task:
		atomic.AddInt64(&e.stats.TasksQueued, 1)
		return nil
	default:
		return ErrQueueFull
	}
}

func (e *InjectionEngine) GetStats() InjectionStats {
	return InjectionStats{
		TasksQueued:  atomic.LoadInt64(&e.stats.TasksQueued),
		TasksSent:    atomic.LoadInt64(&e.stats.TasksSent),
		TasksSuccess: atomic.LoadInt64(&e.stats.TasksSuccess),
		TasksFailed:  atomic.LoadInt64(&e.stats.TasksFailed),
		CharsSent:    atomic.LoadInt64(&e.stats.CharsSent),
		StartTime:    e.stats.StartTime,
	}
}

func (e *InjectionEngine) printStats() {
	stats := e.GetStats()
	log.Printf("[INJECT STATS] Queued: %d | Sent: %d | Success: %d | Failed: %d | Chars: %d",
		stats.TasksQueued, stats.TasksSent, stats.TasksSuccess, stats.TasksFailed, stats.CharsSent)
}

func generateID() string {
	return time.Now().Format("20060102150405.000000000")
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// Errors
var (
	ErrQueueFull = &InjectionError{"Queue is full"}
	ErrNoTarget  = &InjectionError{"Target not found"}
	ErrFailed    = &InjectionError{"Injection failed"}
)

type InjectionError struct {
	msg string
}

func (e *InjectionError) Error() string {
	return e.msg
}
