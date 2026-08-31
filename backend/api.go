package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"
	"unicode/utf8"
	"uuid"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

const MaxUploadSize = 1 * 1024 * 1024

type Server struct {
	db *pgxpool.Pool
}

type AuthenticatedUser struct {
	UserID int64
	OrgID  int64
}

type contextKey int

const userContextKey contextKey = iota

type Document struct {
	Id       int    `json:"id"`
	Filename string `json:"filename"`
}

type DocumentMetadata struct {
	FileType    string `json:"fileType"`
	Description string `json:"description"`
}

type UploadDocument struct {
	OrgID      int64  `json:"orgId"`
	UploadedBy int64  `json:"uploadedBy"`
	Filename   string `json:"filename"`
	MimeType   string `json:"mimeType"`
	Filesize   int64  `json:"filesize"`
	StorageKey string `json:"storageKey"`
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		cookie, err := r.Cookie("session_token")
		if err != nil {
			// TODO: is this error message okay?
			http.Error(w, "session_token cookie not found", http.StatusUnauthorized)
			return
		}

		tokenHashedBytes := sha256.Sum256([]byte(cookie.Value))
		tokenHashed := hex.EncodeToString(tokenHashedBytes[:])

		// TODO: valid_to could be not null?
		query := `
				SELECT m.user_id, m.org_id
				FROM sessions s
				JOIN users u ON s.user_id = u.id
				JOIN user_org_membership m ON m.user_id = u.id AND m.valid_to IS NULL
				WHERE s.token_hash = $1 AND s.expires_at > NOW()`

		var user AuthenticatedUser
		err = s.db.QueryRow(r.Context(), query, tokenHashed).Scan(&user.UserID, &user.OrgID)

		if err == pgx.ErrNoRows {
			http.Error(w, "User could not be authenticated", http.StatusUnauthorized)
			return
		} else if err != nil {
			s.serverError(w, r, "Query in requireAuth", err)
			return
		}

		ctx := context.WithValue(r.Context(), userContextKey, user)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) protected(handler http.HandlerFunc) http.Handler {
	return s.requireAuth(http.HandlerFunc(handler))
}

func (s *Server) contextGetAuthenticatedUser(r *http.Request) AuthenticatedUser {
	user, ok := r.Context().Value(userContextKey).(AuthenticatedUser)
	if !ok { Fatal("missing AuthenticatedUser in context") }
	return user
}

func badRequestEmptyField(w http.ResponseWriter, name string) {
	http.Error(w, fmt.Sprintf("%s is empty", name), http.StatusBadRequest)
}

func (s *Server) registerHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	req := struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}{}

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Bad register request", http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		badRequestEmptyField(w, "Name")
		return
	}

	if req.Email == "" {
		badRequestEmptyField(w, "Email")
		return
	}

	if req.Password == "" {
		badRequestEmptyField(w, "Password")
		return
	}

	if utf8.RuneCountInString(req.Name) > 60 {
		http.Error(w, "Name cannot be longer than 60 chars", http.StatusBadRequest)
		return
	}

	if utf8.RuneCountInString(req.Email) > 255 {
		http.Error(w, "Email cannot be longer than 255 chars", http.StatusBadRequest)
		return
	}

	if utf8.RuneCountInString(req.Password) < 8 {
		http.Error(w, "Password needs to be at least 8 characters", http.StatusBadRequest)
		return
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		s.serverError(w, r, "Could not hash password", err)
		return
	}

	query :=
		`INSERT INTO users (name, email, password_hash)
		 VALUES ($1, $2, $3)
		 RETURNING id`

	var userID int64
	err = s.db.QueryRow(r.Context(), query, req.Name, req.Email, passwordHash).Scan(&userID)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
			http.Error(w, "Email already registered", http.StatusConflict)
			return
		}

		s.serverError(w, r, "Could not insert user", err)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"message": "User registered successfully",
		"id":      userID,
		"name":    req.Name,
		"email":   req.Email,
	})
}

func (s *Server) loginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	req := struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}{}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Bad login request", http.StatusBadRequest)
		return
	}

	userQuery :=
		`SELECT id, password_hash
		 FROM users WHERE email = $1`

	var userID int64
	var passwordHashFromDB string
	err = s.db.QueryRow(r.Context(), userQuery, req.Email).Scan(&userID, &passwordHashFromDB)

	if errors.Is(err, pgx.ErrNoRows) {
		// Prevent identification of valid emails using timing attacks
		dummyBcryptHash := "$2a$10$GbydYFDWd97NCjkoXXl6KuyYH39/fqVg6DfOAMfj9.2YxyoV.K2Gm"
		dummyBcryptPass := "yayPassword"
		bcrypt.CompareHashAndPassword(
			[]byte(dummyBcryptHash),
			[]byte(dummyBcryptPass),
		)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	} else if err != nil {
		s.serverError(w, r, "Error in login user query", err)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(passwordHashFromDB), []byte(req.Password))
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	} else if err != nil {
		s.serverError(w, r, "Error in password and hash compare", err)
		return
	}

	tokenSize := 32
	buf := make([]byte, tokenSize)
	rand.Read(buf)

	tokenHex := hex.EncodeToString(buf)
	tokenHashedBytes := sha256.Sum256([]byte(tokenHex))
	tokenHashed := hex.EncodeToString(tokenHashedBytes[:])
	expiresAt := time.Now().Add(24 * time.Hour)

	querySession :=
		`INSERT INTO sessions (user_id, token_hash, expires_at)
		 VALUES ($1, $2, $3)`

	_, err = s.db.Exec(r.Context(), querySession, userID, tokenHashed, expiresAt)
	if err != nil {
		s.serverError(w, r, "Error in session insert", err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    tokenHex,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   os.Getenv("APP_ENV") == "prod",
		SameSite: http.SameSiteLaxMode,
	})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"message": "User logged in successfully",
	})
}

// TODO: hardcoded, rewrite
func documentsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	docs := []Document{
		{Id: 1, Filename: "Hello"},
		{Id: 2, Filename: "World"},
	}

	json.NewEncoder(w).Encode(docs)
}

func getDocumentPath(storageKey string) string {
	return filepath.Join("./uploads/", storageKey)
}

// TODO: User authentication
func (s *Server) serverError(w http.ResponseWriter, r *http.Request, msg string, err error) {
	slog.ErrorContext(r.Context(), msg, "method", r.Method, "URL", r.URL.Path, "error", err)
	http.Error(w, "Internal server error", http.StatusInternalServerError)
}

func (s *Server) insertDocumentDB(ctx context.Context, doc UploadDocument) error {
	_, err := s.db.Exec(ctx,
		`INSERT INTO documents (org_id, uploaded_by, filename, mime_type, filesize, storage_key)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		doc.OrgID, doc.UploadedBy, doc.Filename, doc.MimeType, doc.Filesize, doc.StorageKey,
	)
	return err
}

func (s *Server) uploadDocumentHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	r.Body = http.MaxBytesReader(w, r.Body, MaxUploadSize)
	if err := r.ParseMultipartForm(MaxUploadSize); err != nil {
		http.Error(w, "File too large or bad request", http.StatusBadRequest)
		return
	}

	jsonString := r.FormValue("fileMetadata")
	if jsonString == "" {
		http.Error(w, "Missing 'fileMetadata' field", http.StatusBadRequest)
		return
	}

	var data DocumentMetadata
	err := json.Unmarshal([]byte(jsonString), &data)
	if err != nil {
		http.Error(w, "Invalid JSON format inside form field", http.StatusBadRequest)
		return
	}
	fmt.Printf("Got metadata: %s\n", data)

	file, handler, err := r.FormFile("fileContent")
	if err != nil {
		http.Error(w, "Error retrieving file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	fmt.Printf("Uploaded File: %s\n", handler.Filename)
	fmt.Printf("File Size: %d bytes\n", handler.Size)

	storageKey := fmt.Sprintf("uploads/%s%s", uuid.New().String(), handler.Filename)

	// First create file, easier to remove if insertDocumentDB fails
	filePath := getDocumentPath(storageKey)
	dst, err := os.Create(filePath)
	if err != nil {
		s.serverError(w, r, "Could not create file in uploadDocumentHandler", err)
		return
	}
	defer dst.Close()
	defer func() {
		if err != nil {
			os.Remove(filePath)
		}
	}()

	uploadDoc := UploadDocument{
		// TODO: rewrite hardcoded constants
		OrgID:      1,
		UploadedBy: 1,
		Filename:   handler.Filename,
		MimeType:   "text/markdown",
		Filesize:   handler.Size,
		StorageKey: storageKey,
	}

	err = s.insertDocumentDB(r.Context(), uploadDoc)
	if err != nil {
		s.serverError(w, r, "Error in insertDocumentDB", err)
		return
	}

	if _, err := io.Copy(dst, file); err != nil {
		s.serverError(w, r, "Could not copy file in uploadDocumentHandler", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	response := map[string]string{"status": "File uploaded successfully!"}
	json.NewEncoder(w).Encode(response)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	response := map[string]string{
		"status": "ok",
	}

	json.NewEncoder(w).Encode(response)
}

func constructDBUrl() string {
	dbUser := getEnvFatal("DB_USER")
	dbPassword := getEnvFatal("DB_PASSWORD")
	dbName := getEnvFatal("DB_NAME")
	dbPort := getEnvFatal("DB_PORT")
	dbHost := "postgres"

	return fmt.Sprintf("postgresql://%s:%s@%s:%s/%s",
		dbUser, dbPassword, dbHost, dbPort, dbName)
}

func getEnvFatal(key string) string {
	out := os.Getenv(key)

	if out == "" {
		slog.Error("Could not find env variable", "var", key)
		os.Exit(1)
	}
	return out
}

func initLogging() {
	var handler slog.Handler

	if os.Getenv("APP_ENV") == "prod" {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})
	} else {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})
	}

	slog.SetDefault(slog.New(handler))

	slog.Info("Slog initialized successfully")
}

func Fatal(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}

func main() {
	if os.Getenv("APP_ENV") == "" {
		err := godotenv.Load()
		if err != nil {
			Fatal("Could not load .env file", "error", err)
		}

		getEnvFatal("APP_ENV")
	}

	initLogging()

	dbUrl := constructDBUrl()
	if dbUrl == "" {
		Fatal("DB_URL environment variable is required")
	}

	ctx := context.Background()

	config, err := pgxpool.ParseConfig(dbUrl)
	if err != nil {
		Fatal("Unable to parse database", "error", err)
	}

	config.MaxConns = 25
	config.MinConns = 5
	config.MaxConnLifetime = 30 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		Fatal("Unable to create connection pool", "error", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		Fatal("Unable to ping database", "error", err)
	}
	slog.Info("Successfully connected to the database pool")

	srv := &Server{db: pool}

	os.MkdirAll("./uploads", os.ModePerm)

	mux := http.NewServeMux()

	// --- Public Routes ---
	mux.HandleFunc("GET /api/health", healthHandler)
	mux.HandleFunc("GET /", homeHandler)
	mux.HandleFunc("POST /api/login", srv.loginHandler)
	mux.HandleFunc("POST /api/register", srv.registerHandler)

	// --- Protected Routes ---
	mux.Handle("GET /api/documents", srv.protected(documentsHandler))
	mux.Handle("POST /api/upload", srv.protected(srv.uploadDocumentHandler))

	slog.Info("Server starting on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		Fatal("Server failed", "error", err)
	}
}

// TODO: Implement handlers
func homeHandler(w http.ResponseWriter, r *http.Request) { w.Write([]byte("Welcome!")) }
