package models

import (
	"golang.org/x/crypto/bcrypt"
	"time"
)

type User struct {
	ID        uint   `gorm:"primaryKey"`
	Username  string `gorm:"unique;not null"`
	Email     string `gorm:"unique;not null"`
	Password  string `gorm:"not null"`
	Role      string `gorm:"default:user"`
	Avatar    string `gorm:"default:'default.png'"`
	Bio       string
	LastLogin time.Time `gorm:"type:datetime;null"` // Permettre NULL
	Threads   []Thread  `gorm:"foreignKey:UserID"`
	Messages  []Message `gorm:"foreignKey:UserID"`
	CreatedAt time.Time
}

func (u *User) HashPassword(password string) error {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		return err
	}
	u.Password = string(bytes)
	return nil
}

func (u *User) CheckPassword(password string) error {
	return bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
}
