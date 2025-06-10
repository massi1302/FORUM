package models

import "time"

type Tag struct {
	ID        uint   `gorm:"primaryKey;type:int unsigned"`
	Name      string `gorm:"not null;unique"`
	CreatedAt time.Time
	Threads   []Thread `gorm:"many2many:thread_tags;"`
}

type Thread struct {
	ID         uint      `gorm:"primaryKey" json:"ID"`
	Title      string    `gorm:"not null" json:"Title"`
	Content    string    `gorm:"not null" json:"Content"`
	UserID     uint      `gorm:"not null" json:"UserID"`
	User       User      `gorm:"foreignKey:UserID" json:"User"`
	CategoryID uint      `gorm:"not null" json:"CategoryID"`
	Category   Category  `gorm:"foreignKey:CategoryID" json:"Category"`
	Status     string    `gorm:"default:active" json:"Status"`
	CreatedAt  time.Time `json:"CreatedAt"`
	UpdatedAt  time.Time `json:"UpdatedAt"`
	Tags       []Tag     `gorm:"many2many:thread_tags;" json:"Tags"`
	Messages   []Message `gorm:"foreignKey:ThreadID" json:"Messages"`
}

type Category struct {
	ID          uint   `gorm:"primaryKey"`
	Name        string `gorm:"not null;unique"`
	Description string
	Threads     []Thread `gorm:"foreignKey:CategoryID"`
	CreatedAt   time.Time
}
