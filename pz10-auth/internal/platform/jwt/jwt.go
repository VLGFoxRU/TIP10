package jwt

import (
	"errors"
	"time"
	"github.com/golang-jwt/jwt/v5"
)

type TokenType string

const (
	AccessToken  TokenType = "access"
	RefreshToken TokenType = "refresh"
)

type Validator interface {
	SignAccess(userID int64, email, role string) (string, error)
	SignRefresh(userID int64, email, role string) (string, error)
	Parse(tokenStr string) (jwt.MapClaims, error)
	VerifyRefresh(tokenStr string) (jwt.MapClaims, error)
}

type HS256 struct {
	secret     []byte
	accessTTL  time.Duration
	refreshTTL time.Duration
}

func NewHS256(secret []byte, accessTTL, refreshTTL time.Duration) *HS256 {
	return &HS256{
		secret:     secret,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
	}
}

func (h *HS256) sign(userID int64, email, role string, ttl time.Duration, tokenType TokenType) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":       userID,
		"email":     email,
		"role":      role,
		"type":      string(tokenType),
		"iat":       now.Unix(),
		"exp":       now.Add(ttl).Unix(),
		"iss":       "pz10-auth",
		"aud":       "pz10-clients",
	}

	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(h.secret)
}

func (h *HS256) SignAccess(userID int64, email, role string) (string, error) {
	return h.sign(userID, email, role, h.accessTTL, AccessToken)
}

func (h *HS256) SignRefresh(userID int64, email, role string) (string, error) {
	return h.sign(userID, email, role, h.refreshTTL, RefreshToken)
}

func (h *HS256) Parse(tokenStr string) (jwt.MapClaims, error) {
	t, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		return h.secret, nil
	},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithAudience("pz10-clients"),
		jwt.WithIssuer("pz10-auth"),
	)

	if err != nil || !t.Valid {
		return nil, errors.New("invalid token")
	}

	claims := t.Claims.(jwt.MapClaims)
	
	// Проверяем, что это access-токен
	if tType, ok := claims["type"]; !ok || tType != string(AccessToken) {
		return nil, errors.New("not an access token")
	}

	return claims, nil
}

func (h *HS256) VerifyRefresh(tokenStr string) (jwt.MapClaims, error) {
	t, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		return h.secret, nil
	},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithAudience("pz10-clients"),
		jwt.WithIssuer("pz10-auth"),
	)

	if err != nil || !t.Valid {
		return nil, errors.New("invalid token")
	}

	claims := t.Claims.(jwt.MapClaims)
	
	// Проверяем, что это refresh-токен
	if tType, ok := claims["type"]; !ok || tType != string(RefreshToken) {
		return nil, errors.New("not a refresh token")
	}

	return claims, nil
}
