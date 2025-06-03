package database

import (
	"forum-educatif/models"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"os"
)

var DB *gorm.DB

func Connect() error {
	dsn := os.Getenv("DB_USER") + ":" + os.Getenv("DB_PASSWORD") +
		"@tcp(" + os.Getenv("DB_HOST") + ":" + os.Getenv("DB_PORT") + ")/" +
		os.Getenv("DB_NAME") + "?charset=utf8mb4&parseTime=True&loc=Local"

	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		return err
	}

	DB = db
	return nil
}

func Migrate() error {
	// Supprimer les tables existantes
	DB.Exec("SET FOREIGN_KEY_CHECKS = 0")

	// Supprimer la table de jointure en premier
	DB.Exec("DROP TABLE IF EXISTS thread_tags")

	// Puis les autres tables
	DB.Exec("DROP TABLE IF EXISTS votes")
	DB.Exec("DROP TABLE IF EXISTS messages")
	DB.Exec("DROP TABLE IF EXISTS threads")
	DB.Exec("DROP TABLE IF EXISTS tags")
	DB.Exec("DROP TABLE IF EXISTS categories")
	DB.Exec("DROP TABLE IF EXISTS users")

	DB.Exec("SET FOREIGN_KEY_CHECKS = 1")

	// Migrer les modèles
	return DB.AutoMigrate(
		&models.User{},
		&models.Category{},
		&models.Tag{},
		&models.Thread{},
		&models.Message{},
		&models.Vote{},
	)
}
