package repo

import (
	"errors"

	"golang.org/x/crypto/bcrypt"

	"example.com/pz10-auth/internal/core"
)

type UserMem struct {
	users map[string]core.UserRecord
}

func NewUserMem() *UserMem {
	hash := func(s string) []byte {
		h, _ := bcrypt.GenerateFromPassword([]byte(s), bcrypt.DefaultCost)
		return h
	}

	return &UserMem{users: map[string]core.UserRecord{
		"admin@example.com": {ID: 1, Email: "admin@example.com", Role: "admin", Hash: hash("secret123")},
		"user@example.com":  {ID: 2, Email: "user@example.com", Role: "user", Hash: hash("secret123")},
	}}
}

var (
	ErrNotFound = errors.New("user not found")
	ErrBadCreds = errors.New("bad credentials")
)

func (r *UserMem) ByEmail(email string) (core.UserRecord, error) {
	u, ok := r.users[email]
	if !ok {
		return core.UserRecord{}, ErrNotFound
	}
	return u, nil
}

func (r *UserMem) ByID(id int64) (core.UserRecord, error) {
	for _, u := range r.users {
		if u.ID == id {
			return u, nil
		}
	}
	return core.UserRecord{}, ErrNotFound
}

func (r *UserMem) CheckPassword(email, pass string) (core.UserRecord, error) {
	u, err := r.ByEmail(email)
	if err != nil {
		return core.UserRecord{}, ErrNotFound
	}

	if bcrypt.CompareHashAndPassword(u.Hash, []byte(pass)) != nil {
		return core.UserRecord{}, ErrBadCreds
	}

	return u, nil
}