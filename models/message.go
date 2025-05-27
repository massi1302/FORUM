package models

import "time"

type Message struct {
	ID        uint   `gorm:"primaryKey"`
	Content   string `gorm:"not null"`
	UserID    uint   // Utiliser UserID de manière cohérente
	User      User   `gorm:"foreignKey:UserID"`
	ThreadID  uint
	Thread    Thread `gorm:"foreignKey:ThreadID"`
	Votes     []Vote `gorm:"foreignKey:MessageID"`
	CreatedAt time.Time
}

type Vote struct {
	ID        uint `gorm:"primaryKey"`
	MessageID uint
	UserID    uint
	Value     int     // 1 pour like, -1 pour dislike
	User      User    `gorm:"foreignKey:UserID"`
	Message   Message `gorm:"foreignKey:MessageID"`
}
