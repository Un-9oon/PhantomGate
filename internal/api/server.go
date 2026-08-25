package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// ══════════════════════════════════════════════════════════════════════════════
// PHANTOMGATE REST API v3.0 — PROGRAMMATIC INTERFACE
// ══════════════════════════════════════════════════════════════════════════════

type APIServer struct {
	addr        string
	port        int
	server      *http.Server
	running     bool
	stopChan    chan struct{}
	
	// Middleware
	middleware  []Middleware
	middlewareMu sync.RWMutex
	
	// Handlers
	routes      map[string]RouteHandler
	routesMu    sync.RWMutex
	
	// Auth
	apiKeys     map[string]*APIKey
	apiKeysMu   sync.RWMutex
	
	// Stats
	stats       *APIStats
	
	// Callbacks
	onRequest   func(*http.Request)
	onResponse  func(http.ResponseWriter, *http.Request)
}

type RouteHandler struct {
	Method  string
	Path    string
	Handler http.HandlerFunc
	Auth    bool
}

type Middleware func(http.HandlerFunc) http.HandlerFunc

type APIKey struct {
	Key         string
	Name        string
	Permissions []string
	ExpiresAt   time.Time
	CreatedAt   time.Time
}

type APIStats struct {
	RequestsTotal   int64
	RequestsSuccess int64
	RequestsError   int64
	StartTime       time.Time
}

type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
	Time    time.Time   `json:"time"`
}

type APIConfig struct {
	Addr        string
	Port        int
	EnableAuth  bool
	APIKeys     []string
}

func NewAPIServer(cfg APIConfig) *APIServer {
	if cfg.Addr == "" {
		cfg.Addr = "0.0.0.0"
	}
	if cfg.Port == 0 {
		cfg.Port = 8080
	}
	
	s := &APIServer{
		addr:     cfg.Addr,
		port:     cfg.Port,
		stopChan: make(chan struct{}),
		routes:   make(map[string]RouteHandler),
		apiKeys:  make(map[string]*APIKey),
		stats: &APIStats{
			StartTime: time.Now(),
		},
	}
	
	// Add default API keys
	for _, key := range cfg.APIKeys {
		s.apiKeys[key] = &APIKey{
			Key:       key,
			Name:      "default",
			CreatedAt: time.Now(),
		}
	}
	
	return s
}

// ══════════════════════════════════════════════════════════════════════════════
// CORE FUNCTIONS
// ══════════════════════════════════════════════════════════════════════════════

func (s *APIServer) Start() error {
	s.running = true
	
	mux := http.NewServeMux()
	
	// Register routes
	s.routesMu.RLock()
	for _, route := range s.routes {
		handler := route.Handler
		if route.Auth {
			handler = s.authMiddleware(handler)
		}
		mux.HandleFunc(route.Path, handler)
	}
	s.routesMu.RUnlock()
	
	// Add default routes
	s.registerDefaultRoutes(mux)
	
	s.server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", s.addr, s.port),
		Handler:      s.loggingMiddleware(mux),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	
	log.Printf("[API] Starting API server on %s:%d", s.addr, s.port)
	
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[API] Server error: %v", err)
		}
	}()
	
	return nil
}

func (s *APIServer) Stop() {
	s.running = false
	close(s.stopChan)
	
	if s.server != nil {
		s.server.Close()
	}
	
	s.printStats()
	log.Printf("[API] API server stopped")
}

// ══════════════════════════════════════════════════════════════════════════════
// ROUTE MANAGEMENT
// ══════════════════════════════════════════════════════════════════════════════

func (s *APIServer) HandleFunc(method, path string, handler http.HandlerFunc, auth bool) {
	s.routesMu.Lock()
	defer s.routesMu.Unlock()
	
	key := fmt.Sprintf("%s %s", method, path)
	s.routes[key] = RouteHandler{
		Method:  method,
		Path:    path,
		Handler: handler,
		Auth:    auth,
	}
}

func (s *APIServer) GET(path string, handler http.HandlerFunc, auth bool) {
	s.HandleFunc("GET", path, handler, auth)
}

func (s *APIServer) POST(path string, handler http.HandlerFunc, auth bool) {
	s.HandleFunc("POST", path, handler, auth)
}

func (s *APIServer) PUT(path string, handler http.HandlerFunc, auth bool) {
	s.HandleFunc("PUT", path, handler, auth)
}

func (s *APIServer) DELETE(path string, handler http.HandlerFunc, auth bool) {
	s.HandleFunc("DELETE", path, handler, auth)
}

// ══════════════════════════════════════════════════════════════════════════════
// DEFAULT ROUTES
// ══════════════════════════════════════════════════════════════════════════════

func (s *APIServer) registerDefaultRoutes(mux *http.ServeMux) {
	// Health check
	mux.HandleFunc("/health", s.handleHealth)
	
	// API info
	mux.HandleFunc("/api", s.handleAPIInfo)
	
	// Status
	mux.HandleFunc("/api/status", s.handleStatus)
	
	// Plugins
	mux.HandleFunc("/api/plugins", s.handlePlugins)
	
	// Sessions
	mux.HandleFunc("/api/sessions", s.handleSessions)
	
	// Credentials
	mux.HandleFunc("/api/credentials", s.handleCredentials)
	
	// Targets
	mux.HandleFunc("/api/targets", s.handleTargets)
	
	// Commands
	mux.HandleFunc("/api/command", s.handleCommand)
}

func (s *APIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.respond(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    map[string]string{"status": "healthy"},
		Time:    time.Now(),
	})
}

func (s *APIServer) handleAPIInfo(w http.ResponseWriter, r *http.Request) {
	s.respond(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"name":    "PhantomGate API",
			"version": "3.0.0",
			"endpoints": []string{
				"/health",
				"/api",
				"/api/status",
				"/api/plugins",
				"/api/sessions",
				"/api/credentials",
				"/api/targets",
				"/api/command",
			},
		},
		Time: time.Now(),
	})
}

func (s *APIServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.respond(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"running": s.running,
			"uptime":  time.Since(s.stats.StartTime).String(),
			"requests": s.stats.RequestsTotal,
		},
		Time: time.Now(),
	})
}

func (s *APIServer) handlePlugins(w http.ResponseWriter, r *http.Request) {
	// TODO: Integrate with plugin manager
	s.respond(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    map[string]interface{}{"plugins": []string{}},
		Time:    time.Now(),
	})
}

func (s *APIServer) handleSessions(w http.ResponseWriter, r *http.Request) {
	// TODO: Integrate with session store
	s.respond(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    map[string]interface{}{"sessions": []string{}},
		Time:    time.Now(),
	})
}

func (s *APIServer) handleCredentials(w http.ResponseWriter, r *http.Request) {
	// TODO: Integrate with credential store
	s.respond(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    map[string]interface{}{"credentials": []string{}},
		Time:    time.Now(),
	})
}

func (s *APIServer) handleTargets(w http.ResponseWriter, r *http.Request) {
	// TODO: Integrate with ARP module
	s.respond(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    map[string]interface{}{"targets": []string{}},
		Time:    time.Now(),
	})
}

func (s *APIServer) handleCommand(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		s.respond(w, http.StatusMethodNotAllowed, APIResponse{
			Success: false,
			Error:   "Method not allowed",
			Time:    time.Now(),
		})
		return
	}
	
	var req struct {
		Command string                 `json:"command"`
		Args    map[string]interface{} `json:"args"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respond(w, http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "Invalid request body",
			Time:    time.Now(),
		})
		return
	}
	
	// TODO: Execute command
	s.respond(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    map[string]interface{}{"result": "Command executed"},
		Time:    time.Now(),
	})
}

// ══════════════════════════════════════════════════════════════════════════════
// MIDDLEWARE
// ══════════════════════════════════════════════════════════════════════════════

func (s *APIServer) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			apiKey = r.URL.Query().Get("api_key")
		}
		
		if apiKey == "" {
			s.respond(w, http.StatusUnauthorized, APIResponse{
				Success: false,
				Error:   "API key required",
				Time:    time.Now(),
			})
			return
		}
		
		s.apiKeysMu.RLock()
		key, exists := s.apiKeys[apiKey]
		s.apiKeysMu.RUnlock()
		
		if !exists {
			s.respond(w, http.StatusUnauthorized, APIResponse{
				Success: false,
				Error:   "Invalid API key",
				Time:    time.Now(),
			})
			return
		}
		
		if !key.ExpiresAt.IsZero() && time.Now().After(key.ExpiresAt) {
			s.respond(w, http.StatusUnauthorized, APIResponse{
				Success: false,
				Error:   "API key expired",
				Time:    time.Now(),
			})
			return
		}
		
		next(w, r)
	}
}

func (s *APIServer) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Call next handler
		next.ServeHTTP(w, r)
		
		// Log request
		duration := time.Since(start)
		log.Printf("[API] %s %s %v", r.Method, r.URL.Path, duration)
		
		atomic.AddInt64(&s.stats.RequestsTotal, 1)
	})
}

// ══════════════════════════════════════════════════════════════════════════════
// API KEY MANAGEMENT
// ══════════════════════════════════════════════════════════════════════════════

func (s *APIServer) AddAPIKey(key, name string, permissions []string, expiresAt time.Time) {
	s.apiKeysMu.Lock()
	defer s.apiKeysMu.Unlock()
	
	s.apiKeys[key] = &APIKey{
		Key:         key,
		Name:        name,
		Permissions: permissions,
		ExpiresAt:   expiresAt,
		CreatedAt:   time.Now(),
	}
}

func (s *APIServer) RemoveAPIKey(key string) {
	s.apiKeysMu.Lock()
	defer s.apiKeysMu.Unlock()
	
	delete(s.apiKeys, key)
}

func (s *APIServer) ValidateAPIKey(key string) bool {
	s.apiKeysMu.RLock()
	defer s.apiKeysMu.RUnlock()
	
	apiKey, exists := s.apiKeys[key]
	if !exists {
		return false
	}
	
	if !apiKey.ExpiresAt.IsZero() && time.Now().After(apiKey.ExpiresAt) {
		return false
	}
	
	return true
}

// ══════════════════════════════════════════════════════════════════════════════
// UTILITY
// ══════════════════════════════════════════════════════════════════════════════

func (s *APIServer) respond(w http.ResponseWriter, status int, response APIResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(response)
}

func (s *APIServer) printStats() {
	log.Printf("[API STATS] Requests: %d", atomic.LoadInt64(&s.stats.RequestsTotal))
}
