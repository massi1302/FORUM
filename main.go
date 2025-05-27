package main

import (
	"forum-educatif/database"
	"forum-educatif/routes"
	"github.com/joho/godotenv"
	"log"
	"os"
)

func main() {
	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

	// Connect to database
	if err := database.Connect(); err != nil {
		log.Fatal("Could not connect to database")
	}

	// Migrate models
	if err := database.Migrate(); err != nil {
		log.Fatal("Could not migrate database")
	}

	// Setup routes
	r := routes.SetupRoutes()

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	r.Run(":" + port)
}
