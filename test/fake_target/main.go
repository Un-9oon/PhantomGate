package main

import (
	"fmt"
	"net/http"
)

// Fake target application that simulates a login portal
func main() {
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<!DOCTYPE html>
<html><body>
<h1>Corporate Login Portal</h1>
<form method="POST" action="/login">
  <input name="username" placeholder="Username"><br>
  <input name="password" type="password" placeholder="Password"><br>
  <button type="submit">Sign In</button>
</form>
</body></html>`)
			return
		}

		// POST: simulate successful login with session cookies
		r.ParseForm()
		user := r.FormValue("username")
		fmt.Printf("[TARGET] Received login: user=%s\n", user)

		// Set fake auth cookies (these should be captured by PhantomGate)
		http.SetCookie(w, &http.Cookie{Name: "session_token", Value: "STOLEN_SESSION_abc123xyz", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "auth_id", Value: "AUTH_ID_secret_987654", Path: "/"})

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><h1>Welcome %s!</h1><p>You are now logged in.</p></body></html>`, user)
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><h1>Home</h1><a href="/login">Login</a></body></html>`)
	})

	fmt.Println("[TARGET] Fake login server running on :9999")
	http.ListenAndServe("127.0.0.1:9999", nil)
}
