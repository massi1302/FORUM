package main

import (
	"forum-educatif/controllers"
	"forum-educatif/database"
	"forum-educatif/middlewares"
	"forum-educatif/routes"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"log"
	"os"
)

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

	// Ajouter les catégories par défaut
	if err := database.EnsureDefaultCategories(); err != nil {
		log.Printf("Warning: Could not create default categories: %v", err)
	}

	// IMPORTANT: Initialiser la connexion à la base de données pour les contrôleurs
	controllers.InitDB(database.DB)
	middlewares.InitDB(database.DB)

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
