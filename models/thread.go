package models

import "time"

type Tag struct {
	ID   uint   `gorm:"primaryKey"`
	Name string `gorm:"not null;unique"`
}

type Thread struct {
	ID        uint `gorm:"primaryKey"`
	Title     string
	Content   string
	Status    string `gorm:"default:open"`
	CreatedAt time.Time
	UpdatedAt time.Time
	UserID    uint
	User      User      `gorm:"foreignKey:UserID"`
	Messages  []Message `gorm:"foreignKey:ThreadID"`
}
