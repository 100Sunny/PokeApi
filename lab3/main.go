package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	MaxBodySize = 10 * 1024 // 10 KB máximo
	Port        = ":8080"
)

var (
	userStore *UserStore
	// Máximo 5 fallos de login por usuario en 5 min -> bloqueo de 5 min
	loginLimiter = NewRateLimiter(5, 5*time.Minute, 5*time.Minute)
	// Máximo 5 intentos de registro por IP en 1 min -> bloqueo de 2 min
	signupLimiter = NewRateLimiter(5, 1*time.Minute, 2*time.Minute)
)

type CredentialsRequest struct {
	Username *string `json:"username"`
	Password *string `json:"password"`
}

// HELPERS DE RESPUESTA Y PARSEO ESTRICTO

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if payload != nil {
		_ = json.NewEncoder(w).Encode(payload)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func getClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Decodifica JSON rechazando campos desconocidos, cuerpos vacíos o basura extra dichos por NewDecoder. Devuelve error si hay un segundo objeto JSON pegado detrás del primero.
func decodeStrictJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields() //Con esto se evitan los campos desconocidos

	if err := dec.Decode(dst); err != nil {
		return err
	}
	// Comprobar que no hay un segundo objeto JSON pegado detrás
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("unexpected extra JSON data")
	}
	return nil
}

func limitBodyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, MaxBodySize) //Hace que la contraseña no ocupe mas de 10KB
		next.ServeHTTP(w, r)
	})
}

// ENDPOINT 1: GET /version

func handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"service": "secure-pokeapi",
		"version": "1.0.0",
	})
}

// ENDPOINT 3: POST /signup

func handleSignup(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	if signupLimiter.IsBlocked(clientIP) {
		writeError(w, http.StatusTooManyRequests, "too many signup attempts, try again later")
		return
	}
	signupLimiter.RegisterAttempt(clientIP)

	var req CredentialsRequest
	if err := decodeStrictJSON(r, &req); err != nil { //Comprueba que este el usuario y la contraseña
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	// Campos obligatorios (evitamos punteros nil o cadenas vacías)
	if req.Username == nil || req.Password == nil || *req.Password == "" {
		writeError(w, http.StatusBadRequest, "missing required fields")
		return
	}

	// Validación de formato (422 Unprocessable Entity)
	if !usernameRegex.MatchString(*req.Username) {
		writeError(w, http.StatusUnprocessableEntity, "invalid username format")
		return
	}

	// Después comprobación de existencia (409 Conflict)
	if err := userStore.CreateUser(*req.Username, *req.Password); err != nil { //Intenta crear el usuario, si ya existe devuelve error
		writeError(w, http.StatusConflict, "username already exists")
		return
	}

	// Respuesta 201 Created sin token ni contraseña
	writeJSON(w, http.StatusCreated, map[string]string{
		"username": *req.Username,
	})
}

// ENDPOINT 2: POST /login

func handleLogin(w http.ResponseWriter, r *http.Request) {
	var req CredentialsRequest
	if err := decodeStrictJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	if req.Username == nil || req.Password == nil || strings.TrimSpace(*req.Username) == "" || *req.Password == "" { //Comprueba que el usuario y la contraseña no sean nulos ni vacíos
		writeError(w, http.StatusBadRequest, "missing required fields")
		return
	}

	username := *req.Username

	// Comprueba si el usuario ha superado el límite de intentos (429 Too Many Requests)
	if loginLimiter.IsBlocked(username) { //Comprueba si el usuario ha superado el límite de intentos de login
		writeError(w, http.StatusTooManyRequests, "too many failed login attempts, account temporarily locked")
		return
	}

	// Mismo mensaje de error (401) si el usuario no existe o si la contraseña falla suma un intento fallido al contador de login
	if !userStore.VerifyCredentials(username, *req.Password) {
		loginLimiter.RegisterAttempt(username)
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	loginLimiter.Reset(username)

	token, err := GenerateAccessToken(username) //Si pasa por todos los controles de fallo de login genera un token de acceso para el usuario
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not generate token")
		return
	}

	// Respuesta 200 OK con el token de acceso
	writeJSON(w, http.StatusOK, map[string]string{
		"token": token,
	})
}

func main() {
	userStore = NewUserStore()

	mux := http.NewServeMux() //Crea un nuevo enrutador para manejar las rutas HTTP

	mux.HandleFunc("GET /version", handleVersion)
	mux.HandleFunc("POST /signup", handleSignup)
	mux.HandleFunc("POST /login", handleLogin)

	mux.HandleFunc("GET /user/{user}/pokedex", handleListPokedex)
	mux.HandleFunc("GET /user/{user}/pokedex/{dex}", handleGetPokemon)
	mux.HandleFunc("PUT /user/{user}/pokedex/{dex}", handlePutPokemon)
	mux.HandleFunc("DELETE /user/{user}/pokedex/{dex}", handleDeletePokemon)

	// Capturar cualquier otra ruta mal formada o intento de path traversal con JSON limpio
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not found")
	})

	fmt.Printf("Servidor PokeAPI escuchando en http://localhost%s\n", Port)
	log.Fatal(http.ListenAndServe(Port, limitBodyMiddleware(mux)))
}
