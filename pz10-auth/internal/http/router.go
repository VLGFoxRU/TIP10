package router

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"example.com/pz10-auth/internal/http/middleware"
	"example.com/pz10-auth/internal/platform/config"
	"example.com/pz10-auth/internal/platform/jwt"
	"example.com/pz10-auth/internal/repo"
	"example.com/pz10-auth/internal/core"
)

func Build(cfg config.Config) http.Handler {
	r := chi.NewRouter()

	userRepo := repo.NewUserMem()
	jwtv := jwt.NewHS256(cfg.JWTSecret, cfg.AccessTTL, cfg.RefreshTTL)
	svc := core.NewService(userRepo, jwtv)
	svc.CleanupBlacklist()

	// Public endpoints
	r.Post("/api/v1/login", svc.LoginHandler)
	r.Post("/api/v1/refresh", svc.RefreshHandler)
	r.Post("/api/v1/logout", svc.LogoutHandler)

	// Protected endpoints
	r.Group(func(auth chi.Router) {
		auth.Use(middleware.AuthN(jwtv))
		auth.Get("/api/v1/me", svc.MeHandler)
		auth.Get("/api/v1/users/{id}", svc.GetUserHandler)

		// Admin-only endpoints
		auth.Group(func(admin chi.Router) {
			admin.Use(middleware.AuthZRoles("admin"))
			admin.Get("/api/v1/admin/stats", svc.AdminStatsHandler)
		})
	})

	return r
}
