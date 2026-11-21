package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// MODELO DE DATOS Y REGLAS DE VALIDACIÓN

type Attack struct {
	Name  *string `json:"name"`
	Type  *string `json:"type"`
	Level *int    `json:"level"`
}

type Pokemon struct {
	Dex     *int     `json:"dex"`
	Name    *string  `json:"name"`
	Types   []string `json:"types"`
	Attacks []Attack `json:"attacks"`
}

type PokemonSummary struct {
	Dex  int    `json:"dex"`
	Name string `json:"name"`
}

// Patrón para el nombre del Pokémon: 2 a 20 caracteres (letras, espacios, guiones, apóstrofos o punto)
var pokemonNameRegex = regexp.MustCompile(`^[a-zA-Z \-'.]{2,20}$`)

// Enumerado estricto de los 18 tipos válidos
var validTypes = map[string]bool{
	"normal": true, "fire": true, "water": true, "grass": true,
	"electric": true, "ice": true, "fighting": true, "poison": true,
	"ground": true, "flying": true, "psychic": true, "bug": true,
	"rock": true, "ghost": true, "dragon": true, "dark": true,
	"steel": true, "fairy": true,
}

// Valida todas las reglas de la Sección 3 (esquema + validaciones cruzadas)
func validatePokemon(p *Pokemon, expectedDex int) error {
	// 1. Campos obligatorios en el Pokémon
	if p.Dex == nil || p.Name == nil || p.Types == nil || p.Attacks == nil {
		return errors.New("missing required pokemon fields")
	}

	// dex entre 1 y 1025, y debe coincidir con el {dex} de la URL
	if *p.Dex < 1 || *p.Dex > 1025 {
		return errors.New("dex must be between 1 and 1025")
	}
	if *p.Dex != expectedDex {
		return errors.New("dex in body does not match URL")
	}

	// Nombre del Pokémon: 2 a 20 caracteres permitidos
	if !pokemonNameRegex.MatchString(*p.Name) {
		return errors.New("invalid pokemon name")
	}

	// Tipos: lista de 1 o 2 elementos válidos y distintos entre sí
	if len(p.Types) < 1 || len(p.Types) > 2 {
		return errors.New("types must have 1 or 2 elements")
	}
	for _, t := range p.Types {
		if !validTypes[t] {
			return errors.New("invalid pokemon type")
		}
	}
	if len(p.Types) == 2 && p.Types[0] == p.Types[1] {
		return errors.New("pokemon cannot have duplicate types")
	}

	// Ataques: lista de 1 a 20 objetos, sin nombres repetidos
	if len(p.Attacks) < 1 || len(p.Attacks) > 20 {
		return errors.New("attacks must have between 1 and 20 elements")
	}

	seenAttackNames := make(map[string]bool)
	for _, atk := range p.Attacks {
		if atk.Name == nil || atk.Type == nil || atk.Level == nil {
			return errors.New("missing required attack fields")
		}
		nameLen := len([]rune(*atk.Name))
		if nameLen < 2 || nameLen > 30 {
			return errors.New("attack name must be between 2 and 30 characters")
		}
		if !validTypes[*atk.Type] {
			return errors.New("invalid attack type")
		}
		if *atk.Level < 1 || *atk.Level > 100 {
			return errors.New("attack level must be between 1 and 100")
		}
		if seenAttackNames[*atk.Name] {
			return errors.New("duplicate attack name")
		}
		seenAttackNames[*atk.Name] = true
	}

	return nil
}

// PARSEO DE {dex} Y RUTAS SEGURAS EN DISCO

// Parsea {dex} como entero estricto entre 1 y 1025 (rechaza "abc", "01", "-5", ...)
func parseStrictDex(raw string) (int, error) {
	if raw == "" {
		return 0, errors.New("empty dex")
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < '0' || raw[i] > '9' {
			return 0, errors.New("dex must be digits only")
		}
	}
	val, err := strconv.Atoi(raw)
	if err != nil || val < 1 || val > 1025 {
		return 0, errors.New("dex out of range")
	}
	// Evitar ceros a la izquierda como "025" si se exige representación canónica
	if strconv.Itoa(val) != raw {
		return 0, errors.New("non-canonical dex integer")
	}
	return val, nil
}

// Construye rutas seguras en disco verificando el usuario y aislando el directorio base
func getSafeUserDir(username string) (string, error) {
	if !usernameRegex.MatchString(username) || !userStore.UserExists(username) {
		return "", errors.New("invalid or unknown user")
	}
	baseDir, err := filepath.Abs("data/pokedex")
	if err != nil {
		return "", err
	}
	userDir := filepath.Join(baseDir, username)
	// Garantizar que la ruta resultante sigue estrictamente dentro de baseDir
	if !strings.HasPrefix(userDir, baseDir+string(os.PathSeparator)) {
		return "", errors.New("path traversal detected")
	}
	return userDir, nil
}

func getSafePokemonFilePath(username string, dex int) (string, error) {
	userDir, err := getSafeUserDir(username)
	if err != nil {
		return "", err
	}
	// El nombre del fichero se deriva exclusivamente del entero validado, nunca de entrada libre
	return filepath.Join(userDir, fmt.Sprintf("%d.json", dex)), nil
}

// CONTROL DE ACCESO (AUTENTICACIÓN + AUTORIZACIÓN)

// Comprueba en el orden exacto de la Sección
// 1. Autenticación -> 401 Unauthorized
// 2. Autorización ({user} == sujeto del token) -> 403 Forbidden
func authenticateAndAuthorize(w http.ResponseWriter, r *http.Request) (string, bool) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		writeError(w, http.StatusUnauthorized, "missing or malformed authorization header")
		return "", false
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenStr == "" {
		writeError(w, http.StatusUnauthorized, "missing token")
		return "", false
	}

	tokenUser, err := ValidateAccessToken(tokenStr)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or expired token")
		return "", false
	}

	// El usuario autenticado viene solo del token verificado
	routeUser := r.PathValue("user")
	if tokenUser != routeUser {
		writeError(w, http.StatusForbidden, "access forbidden for this user")
		return "", false
	}

	return tokenUser, true
}

// ENDPOINT 4: GET /user/{user}/pokedex
func handleListPokedex(w http.ResponseWriter, r *http.Request) {
	user, ok := authenticateAndAuthorize(w, r)
	if !ok {
		return
	}

	userDir, err := getSafeUserDir(user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "storage error")
		return
	}

	entries, err := os.ReadDir(userDir)
	if err != nil {
		if os.IsNotExist(err) {
			writeJSON(w, http.StatusOK, []PokemonSummary{})
			return
		}
		writeError(w, http.StatusInternalServerError, "could not read pokedex")
		return
	}

	summaries := []PokemonSummary{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(userDir, entry.Name()))
		if err != nil {
			continue
		}
		var p Pokemon
		if err := json.Unmarshal(data, &p); err == nil && p.Dex != nil && p.Name != nil {
			summaries = append(summaries, PokemonSummary{
				Dex:  *p.Dex,
				Name: *p.Name,
			})
		}
	}

	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].Dex < summaries[j].Dex
	})

	writeJSON(w, http.StatusOK, summaries)
}

// ENDPOINT 5: GET /user/{user}/pokedex/{dex}
func handleGetPokemon(w http.ResponseWriter, r *http.Request) {
	user, ok := authenticateAndAuthorize(w, r)
	if !ok {
		return
	}

	// Paso 3: Validación de entrada -> 400 si {dex} no es un entero estricto válido
	dex, err := parseStrictDex(r.PathValue("dex"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid dex number")
		return
	}

	filePath, err := getSafePokemonFilePath(user, dex)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "storage error")
		return
	}

	// Paso 4: Existencia del recurso -> 404 Not Found
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			writeError(w, http.StatusNotFound, "pokemon not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not read pokemon")
		return
	}

	var p Pokemon
	if err := json.Unmarshal(data, &p); err != nil {
		writeError(w, http.StatusInternalServerError, "corrupted pokemon entry")
		return
	}

	writeJSON(w, http.StatusOK, p)
}

// ENDPOINT 6: PUT /user/{user}/pokedex/{dex}
func handlePutPokemon(w http.ResponseWriter, r *http.Request) {
	user, ok := authenticateAndAuthorize(w, r)
	if !ok {
		return
	}

	// Paso 3a: Validar {dex} de la URL -> 400 Bad Request
	dex, err := parseStrictDex(r.PathValue("dex"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid dex number")
		return
	}

	// Paso 3b: Sintaxis JSON estricta y campos extra -> 400 Bad Request
	var p Pokemon
	if err := decodeStrictJSON(r, &p); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	// Paso 3c: Reglas de esquema y validaciones cruzadas -> 422 Unprocessable Entity
	if err := validatePokemon(&p, dex); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	filePath, err := getSafePokemonFilePath(user, dex)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "storage error")
		return
	}

	if err := os.MkdirAll(filepath.Dir(filePath), 0700); err != nil {
		writeError(w, http.StatusInternalServerError, "could not create storage directory")
		return
	}

	// Comprobar si ya existía para devolver 200 OK (reemplazo) o 201 Created (creación)
	existed := false
	if _, err := os.Stat(filePath); err == nil {
		existed = true
	}

	encoded, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not encode pokemon")
		return
	}

	if err := os.WriteFile(filePath, encoded, 0600); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save pokemon")
		return
	}

	if existed {
		writeJSON(w, http.StatusOK, p)
	} else {
		writeJSON(w, http.StatusCreated, p)
	}
}

// ENDPOINT 7: DELETE /user/{user}/pokedex/{dex}
func handleDeletePokemon(w http.ResponseWriter, r *http.Request) {
	user, ok := authenticateAndAuthorize(w, r)
	if !ok {
		return
	}

	// Paso 3: Validar {dex} -> 400 Bad Request
	dex, err := parseStrictDex(r.PathValue("dex"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid dex number")
		return
	}

	filePath, err := getSafePokemonFilePath(user, dex)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "storage error")
		return
	}

	// Paso 4: Existencia del recurso -> 404 Not Found
	if err := os.Remove(filePath); err != nil {
		if os.IsNotExist(err) {
			writeError(w, http.StatusNotFound, "pokemon not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not delete pokemon")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
