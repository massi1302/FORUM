package models

import (
	"time"
)

type Post struct {
	ID        uint      `gorm:"primaryKey" json:"ID"`
	Content   string    `gorm:"not null" json:"Content"`
	UserID    uint      `gorm:"not null" json:"UserID"`
	User      User      `gorm:"foreignKey:UserID" json:"User"`
	CreatedAt time.Time `json:"CreatedAt"`
	UpdatedAt time.Time `json:"UpdatedAt"`
	Likes     int       `gorm:"default:0" json:"Likes"`
	Image     string    `json:"Image"` // URL de l'image (optionnel)
	Comments  []Comment `gorm:"foreignKey:PostID" json:"Comments"`
}

type Comment struct {
	ID        uint      `gorm:"primaryKey" json:"ID"`
	Content   string    `gorm:"not null" json:"Content"`
	UserID    uint      `gorm:"not null" json:"UserID"`
	User      User      `gorm:"foreignKey:UserID" json:"User"`
	PostID    uint      `gorm:"not null" json:"PostID"`
	CreatedAt time.Time `json:"CreatedAt"`
	UpdatedAt time.Time `json:"UpdatedAt"`
}
