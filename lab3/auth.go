package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	UsersFilePath = "data/users.json"
	TokenTTL      = 15 * time.Minute // Caducidad de 15 minutos
	BcryptCost    = 12               // Coste alto para frenar fuerza bruta offline
)

// Patrón estricto exigido: 3 a 20 caracteres, minúsculas, dígitos y guion bajo
var usernameRegex = regexp.MustCompile(`^[a-z0-9_]{3,20}$`)

// Clave secreta generada aleatoriamente en memoria al arrancar el servidor
var jwtSecretKey []byte

func init() {
	jwtSecretKey = make([]byte, 32)                    //Hace la clave de 32 bytes
	if _, err := rand.Read(jwtSecretKey); err != nil { //la hace aleatoria, para firmar los tokens y evitar falsificaciones
		panic("failed to generate cryptographic secret key")
	}
}

// ALMACENAMIENTO DE USUARIOS

type UserStore struct {
	mu    sync.RWMutex      //Un mutex por si se escribe a la vz no se corrompa
	users map[string]string // guarda username -> password_hash
}

func NewUserStore() *UserStore {
	store := &UserStore{
		users: make(map[string]string),
	}
	store.load()
	return store
}

func (s *UserStore) load() {
	data, err := os.ReadFile(UsersFilePath)
	if err == nil {
		_ = json.Unmarshal(data, &s.users) //  Si hay error, se ignora y se empieza con un mapa vacío
	}
}

func (s *UserStore) save() error {
	if err := os.MkdirAll(filepath.Dir(UsersFilePath), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.users, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(UsersFilePath, data, 0600)
}

func (s *UserStore) CreateUser(username, password string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[username]; exists {
		return errors.New("user already exists")
	}

	// Añade una sal aleatoria y cifra la clave para que nunca se guarde en claro
	hash, err := bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
	if err != nil {
		return err
	}

	s.users[username] = string(hash)
	return s.save()
}

func (s *UserStore) VerifyCredentials(username, password string) bool {
	s.mu.RLock()
	hash, exists := s.users[username]
	s.mu.RUnlock()

	if !exists {
		// Ejecutamos una comparación falsa para mitigar ataques de temporización (timing attacks)
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"), []byte(password))
		return false
	}

	// Comparación en tiempo constante proporcionada por bcrypt
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func (s *UserStore) UserExists(username string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, exists := s.users[username]
	return exists
}

// GESTIÓN DE TOKENS JWT

func GenerateAccessToken(username string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": username,
		"iat": now.Unix(),
		"exp": now.Add(TokenTTL).Unix(), //Fecha de caducidad, tiempo +15
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecretKey)
}

func ValidateAccessToken(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		// Evitar ataques de confusión de algoritmo
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return jwtSecretKey, nil
	})

	//Comprueba que el token no esté manipulado y que no hayan pasado esos 15 minutos
	if err != nil || !token.Valid {
		return "", errors.New("invalid or expired token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("invalid token claims")
	}

	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return "", errors.New("invalid subject in token")
	}

	return sub, nil
}

// RATE LIMITER (PROTECCIÓN LOGIN Y SIGNUP)

type attemptRecord struct {
	count        int
	blockedUntil time.Time
	windowStart  time.Time
}

type RateLimiter struct {
	//Lleva recuento de las contraseñas para que despues de ciertas veces se bloquee el login o el signup
	mu          sync.Mutex
	records     map[string]*attemptRecord
	maxAttempts int
	window      time.Duration
	blockTime   time.Duration
}

func NewRateLimiter(maxAttempts int, window, blockTime time.Duration) *RateLimiter {
	return &RateLimiter{
		records:     make(map[string]*attemptRecord),
		maxAttempts: maxAttempts,
		window:      window,
		blockTime:   blockTime,
	}
}

func (rl *RateLimiter) IsBlocked(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rec, exists := rl.records[key]
	if !exists {
		return false
	}

	now := time.Now()
	if !rec.blockedUntil.IsZero() {
		if now.Before(rec.blockedUntil) {
			return true
		}
		// El bloqueo ha expirado: reiniciamos
		delete(rl.records, key)
		return false
	}

	if now.Sub(rec.windowStart) > rl.window {
		delete(rl.records, key)
		return false
	}

	return false
}

func (rl *RateLimiter) RegisterAttempt(key string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	rec, exists := rl.records[key]
	if !exists || now.Sub(rec.windowStart) > rl.window {
		rl.records[key] = &attemptRecord{
			count:       1,
			windowStart: now,
		}
		return
	}

	rec.count++
	if rec.count >= rl.maxAttempts {
		rec.blockedUntil = now.Add(rl.blockTime)
	}
}

func (rl *RateLimiter) Reset(key string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.records, key)
}
