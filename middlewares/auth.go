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

func SetUserToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		isLoggedIn := false // Par défaut, l'utilisateur n'est pas connecté

		// Si l'en-tête Authorization est vide, vérifier les cookies
		if authHeader == "" {
			tokenCookie, err := c.Cookie("token")
			if err == nil {
				authHeader = "Bearer " + tokenCookie
			}
		}

		if authHeader != "" {
			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				return []byte(os.Getenv("JWT_SECRET")), nil
			})

			if err == nil && token.Valid {
				claims, ok := token.Claims.(jwt.MapClaims)
				if ok {
					fmt.Printf("Type de claims[\"sub\"]: %T, Valeur: %v\n", claims["sub"], claims["sub"])
					c.Set("userID", claims["sub"])
					c.Set("token", tokenString)
					c.Set("isLoggedIn", true)

					var user models.User

					if sub, ok := claims["sub"].(float64); ok {
						if DB.First(&user, uint(sub)).Error == nil {
							c.Set("isAdmin", user.Role == "admin")
						}
					}

				}
			}
		}

		// Définir isLoggedIn de manière explicite dans le contexte
		c.Set("isLoggedIn", isLoggedIn)

		c.Next()
	}
}
