package middlewares

import (
	"fmt"
	"forum-educatif/models"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB(db *gorm.DB) {
	DB = db
}

func Auth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Vérifier le token dans les headers Authorization
		authHeader := c.GetHeader("Authorization")

		// Aussi vérifier dans les cookies
		if authHeader == "" {
			tokenCookie, err := c.Cookie("token")
			if err == nil {
				authHeader = "Bearer " + tokenCookie
			}
		}

		if authHeader == "" {
			formAuth := c.PostForm("Authorization")
			if formAuth != "" {
				authHeader = formAuth
			}
		}

		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("JWT_SECRET")), nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			c.Abort()
			return
		}

		c.Set("userID", claims["sub"])
		c.Next()
	}
}

func Admin() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("userID")
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
			return
		}

		var user models.User
		if err := DB.First(&user, userID).Error; err != nil {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}

		if user.Role != "admin" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
			return
		}

		c.Next()
	}
}

func SetUserAuthInfo() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Définir isLoggedIn à false par défaut
		c.Set("isLoggedIn", false)

		// Vérifier si le token existe dans les cookies
		tokenString, err := c.Cookie("token")
		if err == nil && tokenString != "" {
			// Valider le token
			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				return []byte(os.Getenv("JWT_SECRET")), nil
			})

			if err == nil && token.Valid {
				if claims, ok := token.Claims.(jwt.MapClaims); ok {
					// Définir les variables dans le contexte
					userID := claims["sub"]
					c.Set("userID", userID)
					c.Set("token", tokenString)
					c.Set("isLoggedIn", true)

					// Récupérer les infos de l'utilisateur pour vérifier le rôle
					var user models.User
					if err := DB.First(&user, userID).Error; err == nil {
						c.Set("userRole", user.Role)
						c.Set("isAdmin", user.Role == "admin")
					}
				}
			}
		}

		c.Next()
	}
}

func SearchThreads(c *gin.Context) {
	// Récupérer le terme de recherche
	query := c.Query("q")
	if query == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Le terme de recherche est vide"})
		return
	}

	// Vérifier si la recherche est un tag (commence par #)
	var threads []models.Thread
	var totalResults int64

	if strings.HasPrefix(query, "#") {
		// Recherche par tag (enlever le # du début)
		tagName := strings.TrimPrefix(query, "#")

		// Trouver d'abord le tag
		var tag models.Tag
		if err := DB.Where("name LIKE ?", tagName).First(&tag).Error; err != nil {
			// Si le tag n'existe pas, retourner un résultat vide
			c.JSON(http.StatusOK, gin.H{
				"threads": []models.Thread{},
				"total":   0,
				"query":   query,
			})
			return
		}

		// Trouver les threads associés à ce tag
		if err := DB.Model(&models.Thread{}).
			Joins("JOIN thread_tags ON threads.id = thread_tags.thread_id").
			Where("thread_tags.tag_id = ?", tag.ID).
			Count(&totalResults).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur de base de données"})
			return
		}

		if err := DB.Preload("User").Preload("Category").Preload("Tags").
			Joins("JOIN thread_tags ON threads.id = thread_tags.thread_id").
			Where("thread_tags.tag_id = ?", tag.ID).
			Find(&threads).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur de base de données"})
			return
		}
	} else {
		// Recherche par titre
		searchTerm := "%" + query + "%"

		if err := DB.Model(&models.Thread{}).
			Where("title LIKE ? OR content LIKE ?", searchTerm, searchTerm).
			Count(&totalResults).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur de base de données"})
			return
		}

		if err := DB.Preload("User").Preload("Category").Preload("Tags").
			Where("title LIKE ? OR content LIKE ?", searchTerm, searchTerm).
			Find(&threads).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur de base de données"})
			return
		}
	}

	// Vérifier le format de réponse demandé
	if c.GetHeader("Accept") == "application/json" {
		c.JSON(http.StatusOK, gin.H{
			"threads": threads,
			"total":   totalResults,
			"query":   query,
		})
	} else {
		// Retourner une page HTML
		c.HTML(http.StatusOK, "search_results.html", gin.H{
			"title":      "Résultats de recherche pour: " + query,
			"threads":    threads,
			"total":      totalResults,
			"query":      query,
			"isLoggedIn": c.GetBool("isLoggedIn"),
			"userID":     c.GetUint("userID"),
		})
	}
}
