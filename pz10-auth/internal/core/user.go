package core

type User struct {
	ID    int64
	Email string
	Role  string
}

// UserRecord — общий тип для всех пакетов
type UserRecord struct {
	ID    int64
	Email string
	Role  string
	Hash  []byte
}