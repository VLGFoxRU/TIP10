package config

import (
	"log"
	"os"
	"time"
)

type Config struct {
	Port     string
	JWTSecret []byte
	AccessTTL     time.Duration
	RefreshTTL    time.Duration
}

func Load() Config {
	port := os.Getenv("APP_PORT")
	if port == "" { port = "8080" }

	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Fatal("JWT_SECRET is required")
	}

	accessTTL := os.Getenv("ACCESS_TTL")
	if accessTTL == "" {
		accessTTL = "15m"
	}

	aDur, err := time.ParseDuration(accessTTL)
	if err != nil {
		log.Fatal("bad ACCESS_TTL:", err)
	}
	refreshTTL := os.Getenv("REFRESH_TTL")
	if refreshTTL == "" {
		refreshTTL = "168h" // 7 дней
	}
	rDur, err := time.ParseDuration(refreshTTL)
	if err != nil {
		log.Fatal("bad REFRESH_TTL:", err)
	}

	return Config{
		Port:       ":" + port,
		JWTSecret:  []byte(secret),
		AccessTTL:  aDur,
		RefreshTTL: rDur,
	}
}
