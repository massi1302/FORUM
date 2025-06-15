package main

import (
	"fmt"
	"forum-educatif/controllers"
	"forum-educatif/database"
	"forum-educatif/middlewares"
	"forum-educatif/models"
	"forum-educatif/routes"
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

func createAdminUserIfNotExists() {
	var adminCount int64
	database.DB.Model(&models.User{}).Where("role = ?", "admin").Count(&adminCount)

	if adminCount == 0 {
		// Créer un admin par défaut
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
		admin := models.User{
			Username: "admin",
			Email:    "admin@forum.com",
			Password: string(hashedPassword),
			Role:     "admin",
		}
		database.DB.Create(&admin)
		fmt.Println("Compte administrateur créé avec succès")
	}
}

func main() {

	// Charger les variables d'environnement
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

	// Connecter à la base de données
	if err := database.Connect(); err != nil {
		log.Fatalf("Could not connect to database: %v", err)
	}

	// Migrer les modèles
	if err := database.Migrate(); err != nil {
		log.Fatalf("Could not migrate database: %v", err)
	}

	// IMPORTANT: Initialiser la connexion à la base de données pour les contrôleurs
	controllers.InitDB(database.DB)
	middlewares.InitDB(database.DB)

	// Ajouter les catégories par défaut
	if err := database.EnsureDefaultCategories(); err != nil {
		log.Printf("Warning: Could not create default categories: %v", err)
	}

	createAdminUserIfNotExists()

	// Créer le routeur Gin
	r := gin.Default()

	// Configurer les routes
	routes.SetupRoutes(r)

	// Démarrer le serveur
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Server running on port %s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
