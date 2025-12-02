package core

import (
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"example.com/pz10-auth/internal/http/middleware"
)

type userRepo interface {
	CheckPassword(email, pass string) (UserRecord, error)
	ByID(id int64) (UserRecord, error)
}

type jwtSigner interface {
	SignAccess(userID int64, email, role string) (string, error)
	SignRefresh(userID int64, email, role string) (string, error)
	Parse(tokenStr string) (jwt.MapClaims, error)
	VerifyRefresh(tokenStr string) (jwt.MapClaims, error)
}

type Service struct {
	repo               userRepo
	jwt                jwtSigner
	refreshBlacklist   map[string]time.Time
	refreshBlacklistMu sync.RWMutex
}

func NewService(r userRepo, j jwtSigner) *Service {
	return &Service{
		repo:             r,
		jwt:              j,
		refreshBlacklist: make(map[string]time.Time),
	}
}

func (s *Service) CleanupBlacklist() {
	ticker := time.NewTicker(1 * time.Minute)
	go func() {
		for range ticker.C {
			s.refreshBlacklistMu.Lock()
			now := time.Now()
			for token, exp := range s.refreshBlacklist {
				if exp.Before(now) {
					delete(s.refreshBlacklist, token)
				}
			}
			s.refreshBlacklistMu.Unlock()
		}
	}()
}

func (s *Service) isRefreshBlacklisted(token string) bool {
	s.refreshBlacklistMu.RLock()
	defer s.refreshBlacklistMu.RUnlock()
	_, exists := s.refreshBlacklist[token]
	return exists
}

func (s *Service) addToBlacklist(token string, exp time.Time) {
	s.refreshBlacklistMu.Lock()
	defer s.refreshBlacklistMu.Unlock()
	s.refreshBlacklist[token] = exp
}

func (s *Service) LoginHandler(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Email == "" || in.Password == "" {
		httpError(w, 400, "invalid_credentials")
		return
	}

	u, err := s.repo.CheckPassword(in.Email, in.Password)
	if err != nil {
		httpError(w, 401, "unauthorized")
		return
	}

	access, err := s.jwt.SignAccess(u.ID, u.Email, u.Role)
	if err != nil {
		httpError(w, 500, "token_error")
		return
	}

	refresh, err := s.jwt.SignRefresh(u.ID, u.Email, u.Role)
	if err != nil {
		httpError(w, 500, "token_error")
		return
	}

	jsonOK(w, map[string]string{
		"access":  access,
		"refresh": refresh,
	})
}

func (s *Service) RefreshHandler(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RefreshToken string `json:"refresh"`
	}

	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.RefreshToken == "" {
		httpError(w, 400, "refresh_token_required")
		return
	}

	if s.isRefreshBlacklisted(in.RefreshToken) {
		httpError(w, 401, "token_revoked")
		return
	}

	claims, err := s.jwt.VerifyRefresh(in.RefreshToken)
	if err != nil {
		httpError(w, 401, "unauthorized")
		return
	}

	userID := int64(claims["sub"].(float64))
	email := claims["email"].(string)
	role := claims["role"].(string)

	access, err := s.jwt.SignAccess(userID, email, role)
	if err != nil {
		httpError(w, 500, "token_error")
		return
	}

	newRefresh, err := s.jwt.SignRefresh(userID, email, role)
	if err != nil {
		httpError(w, 500, "token_error")
		return
	}

	s.addToBlacklist(in.RefreshToken, time.Unix(int64(claims["exp"].(float64)), 0))

	jsonOK(w, map[string]string{
		"access":  access,
		"refresh": newRefresh,
	})
}

func (s *Service) MeHandler(w http.ResponseWriter, r *http.Request) {
	// Используйте middleware.ContextClaimsKey (типизированный ключ!)
	claimsVal := r.Context().Value(middleware.ContextClaimsKey)
	if claimsVal == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized"}`))
		return
	}

	claims, ok := claimsVal.(map[string]any)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"id":    claims["sub"],
		"email": claims["email"],
		"role":  claims["role"],
	})
}



func (s *Service) GetUserHandler(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httpError(w, 400, "bad_id")
		return
	}

	claims := r.Context().Value(ContextClaimsKey).(map[string]any)
	userID := int64(claims["sub"].(float64))
	role := claims["role"].(string)

	// ABAC: user может получить только свой профиль, admin может любой
	if role == "user" && userID != id {
		httpError(w, 403, "forbidden")
		return
	}

	u, err := s.repo.ByID(id)
	if err != nil {
		httpError(w, 404, "user_not_found")
		return
	}

	jsonOK(w, map[string]any{
		"id":    u.ID,
		"email": u.Email,
		"role":  u.Role,
	})
}

func (s *Service) AdminStatsHandler(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]any{
		"total_users": 2,
		"version":     "1.0",
		"timestamp":   time.Now().Unix(),
	})
}

func (s *Service) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RefreshToken string `json:"refresh"`
	}

	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.RefreshToken == "" {
		httpError(w, 400, "refresh_token_required")
		return
	}

	claims, err := s.jwt.VerifyRefresh(in.RefreshToken)
	if err == nil {
		s.addToBlacklist(in.RefreshToken, time.Unix(int64(claims["exp"].(float64)), 0))
	}

	jsonOK(w, map[string]string{"status": "logged_out"})
}

// === Утилиты ===

type ContextKey int

const ContextClaimsKey ContextKey = iota

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}