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

		// Chercher le token dans le header d'autorisation
		tokenString := c.GetHeader("Authorization")
		if tokenString != "" {
			// Si le token est dans le header, enlever le préfixe "Bearer "
			if len(tokenString) > 7 && strings.ToUpper(tokenString[0:7]) == "BEARER " {
				tokenString = tokenString[7:]
			}
		} else {
			// Si pas dans le header, chercher dans les cookies
			var err error
			tokenString, err = c.Cookie("token")
			if err != nil {
				// Pas de token, continuer sans authentification
				c.Next()
				return
			}
		}

		// Valider le token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(os.Getenv("JWT_SECRET")), nil
		})

		if err != nil || !token.Valid {
			// Token invalide, continuer sans authentification
			c.Next()
			return
		}

		// Token valide, extraire les claims
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			// Définir les variables dans le contexte
			userID := claims["sub"]
			c.Set("userID", userID)
			c.Set("token", tokenString)
			c.Set("isLoggedIn", true)

			// Vérifier si l'utilisateur est admin (optionnel)
			var user models.User
			if err := DB.First(&user, userID).Error; err == nil && user.Role == "admin" {
				c.Set("isAdmin", true)
			}
		}

		c.Next()
	}
}
