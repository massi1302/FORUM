package models

import "time"

type Tag struct {
	ID        uint   `gorm:"primaryKey"`
	Name      string `gorm:"not null;unique"`
	CreatedAt time.Time
	Threads   []Thread `gorm:"many2many:thread_tags;"`
}

type Thread struct {
	ID         uint `gorm:"primaryKey"`
	Title      string
	Content    string
	Status     string `gorm:"default:open"`
	CreatedAt  time.Time
	UpdatedAt  time.Time
	UserID     uint
	User       User      `gorm:"foreignKey:UserID"`
	Messages   []Message `gorm:"foreignKey:ThreadID"`
	CategoryID uint
	Category   Category `gorm:"foreignKey:CategoryID"`
	Tags       []Tag    `gorm:"many2many:thread_tags;"`
}

type Category struct {
	ID          uint   `gorm:"primaryKey"`
	Name        string `gorm:"not null;unique"`
	Description string
	Threads     []Thread `gorm:"foreignKey:CategoryID"`
	CreatedAt   time.Time
}
