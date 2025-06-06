package database

import (
	"forum-educatif/models"
	"os"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
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

func EnsureDefaultCategories() error {
	// Vérifier si des catégories existent déjà
	var count int64
	DB.Model(&models.Category{}).Count(&count)

	// Si aucune catégorie n'existe, créer les catégories par défaut
	if count == 0 {
		categories := []models.Category{
			{
				Name:        "Général",
				Description: "Discussions générales et sujets divers",
				CreatedAt:   time.Now(),
			},
			{
				Name:        "Programmation",
				Description: "Discussions sur les langages de programmation, frameworks et outils de développement",
				CreatedAt:   time.Now(),
			},
			{
				Name:        "Mathématiques",
				Description: "Discussions sur les mathématiques, les formules et les théorèmes",
				CreatedAt:   time.Now(),
			},
			{
				Name:        "Sciences",
				Description: "Discussions sur la physique, la chimie, la biologie et autres sciences",
				CreatedAt:   time.Now(),
			},
			{
				Name:        "Langues",
				Description: "Discussions sur l'apprentissage des langues et la linguistique",
				CreatedAt:   time.Now(),
			},
			{
				Name:        "Art et Culture",
				Description: "Discussions sur l'art, la littérature, la musique et la culture",
				CreatedAt:   time.Now(),
			},
			{
				Name:        "Technologie",
				Description: "Discussions sur les nouvelles technologies, gadgets et innovations",
				CreatedAt:   time.Now(),
			},
		}

		// Insérer toutes les catégories dans la base de données
		return DB.Create(&categories).Error
	}

	return nil
}
