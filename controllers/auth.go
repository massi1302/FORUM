package controllers

import (
	"fmt" // Ajoutez cet import
	"forum-educatif/models"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB(db *gorm.DB) {
	DB = db
}

func Register(c *gin.Context) {
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Password validation
	if len(user.Password) < 12 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Le mot de passe doit comporter au moins 12 caractères"})
		return
	}

	// Vérifier la présence d'une majuscule
	hasUpperCase := false
	for _, char := range user.Password {
		if unicode.IsUpper(char) {
			hasUpperCase = true
			break
		}
	}
	if !hasUpperCase {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Le mot de passe doit contenir au moins une majuscule"})
		return
	}

	// Vérifier la présence d'un caractère spécial
	hasSpecialChar := false
	specialChars := "!@#$%^&*()_+-=[]{}|;:,.<>?/"
	for _, char := range user.Password {
		if strings.ContainsRune(specialChars, char) {
			hasSpecialChar = true
			break
		}
	}
	if !hasSpecialChar {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Le mot de passe doit contenir au moins un caractère spécial"})
		return
	}

	// Hash password
	if err := user.HashPassword(user.Password); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not hash password"})
		return
	}

	user.LastLogin = time.Now()

	// Create user
	if err := DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User created successfully"})
}

func Login(c *gin.Context) {
	var credentials struct {
		Identifier string `json:"identifier"`
		Password   string `json:"password"`
	}

	if err := c.ShouldBindJSON(&credentials); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.User
	if err := DB.Where("username = ? OR email = ?", credentials.Identifier, credentials.Identifier).First(&user).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if err := user.CheckPassword(credentials.Password); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Create JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
		return
	}

	// Update last login
	user.LastLogin = time.Now()
	DB.Save(&user)

	c.SetCookie("token", tokenString, 3600*24, "/", "", false, true)

	c.JSON(http.StatusOK, gin.H{
		"token": tokenString,
		"user": gin.H{
			"id":       user.ID,
			"username": user.Username,
			"email":    user.Email,
			"role":     user.Role,
		},
	})
}

func GetAllUsers(c *gin.Context) {
	var users []models.User
	if err := DB.Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not retrieve users"})
		return
	}

	c.JSON(http.StatusOK, users)
}

func BanUser(c *gin.Context) {
	var user models.User
	userID := c.Param("id")

	if err := DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Soft delete the user
	if err := DB.Delete(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not ban user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User banned successfully"})
}

func ChangeThreadStatus(c *gin.Context) {
	var thread models.Thread
	threadID := c.Param("id")

	if err := DB.First(&thread, threadID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Thread not found"})
		return
	}

	var status struct {
		Status string `json:"status"`
	}
	if err := c.ShouldBindJSON(&status); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	thread.Status = status.Status
	if err := DB.Save(&thread).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not update thread status"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Thread status updated successfully"})
}

func UpdateThread(c *gin.Context) {
	var thread models.Thread
	threadID := c.Param("id")

	if err := DB.First(&thread, threadID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Thread not found"})
		return
	}

	if err := c.ShouldBindJSON(&thread); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := DB.Save(&thread).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not update thread"})
		return
	}

	c.JSON(http.StatusOK, thread)
}

func CreateThread(c *gin.Context) {
	var thread models.Thread
	if err := c.ShouldBindJSON(&thread); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Conversion correcte de float64 à uint
	floatID, ok := userID.(float64)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user ID format"})
		return
	}
	thread.UserID = uint(floatID)

	if err := DB.Create(&thread).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create thread"})
		return
	}

	c.JSON(http.StatusCreated, thread)
}

func GetThread(c *gin.Context) {
	threadID := c.Param("id")
	var thread models.Thread

	// Récupérer le paramètre de tri
	sortBy := c.DefaultQuery("sort", "recent") // Par défaut, tri par date

	// Charger le thread avec ses messages
	if err := DB.Preload("User").First(&thread, threadID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Thread not found"})
		return
	}

	// Charger les messages selon le tri demandé
	var messages []models.Message

	if sortBy == "popular" {
		// Tri par popularité (likes - dislikes)
		DB.Model(&models.Message{}).
			Select("messages.*, COALESCE(SUM(votes.value), 0) as vote_count").
			Joins("LEFT JOIN votes ON votes.message_id = messages.id").
			Where("messages.thread_id = ?", threadID).
			Group("messages.id").
			Order("vote_count DESC").
			Preload("User").
			Find(&messages)
	} else {
		// Tri chronologique (du plus récent au plus ancien)
		DB.Where("thread_id = ?", threadID).
			Order("created_at DESC").
			Preload("User").
			Find(&messages)
	}

	// Assigner les messages au thread
	thread.Messages = messages

	c.JSON(http.StatusOK, thread)
}

func GetThreads(c *gin.Context) {
	var threads []models.Thread
	if err := DB.Preload("User").Find(&threads).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not retrieve threads"})
		return
	}

	c.JSON(http.StatusOK, threads)
}

func CreateMessage(c *gin.Context) {
	var message models.Message

	// Vérifier le type de contenu
	contentType := c.GetHeader("Content-Type")
	if contentType == "application/json" {
		if err := c.ShouldBindJSON(&message); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	} else {
		// Traitement du formulaire HTML
		threadIDStr := c.PostForm("ThreadID")
		content := c.PostForm("Content")

		if threadIDStr == "" || content == "" {
			c.Redirect(http.StatusFound, "/threads")
			return
		}

		threadID, err := strconv.Atoi(threadIDStr)
		if err != nil {
			c.Redirect(http.StatusFound, "/threads")
			return
		}

		message.ThreadID = uint(threadID)
		message.Content = content
	}

	userID, exists := c.Get("userID")
	if !exists {
		if contentType == "application/json" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		} else {
			c.Redirect(http.StatusFound, "/login")
		}
		return
	}

	// Conversion correcte de float64 à uint
	floatID, ok := userID.(float64)
	if !ok {
		if contentType == "application/json" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user ID format"})
		} else {
			c.Redirect(http.StatusFound, "/threads")
		}
		return
	}
	message.UserID = uint(floatID)

	if err := DB.Create(&message).Error; err != nil {
		if contentType == "application/json" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create message"})
		} else {
			c.Redirect(http.StatusFound, "/threads")
		}
		return
	}

	if contentType == "application/json" {
		c.JSON(http.StatusCreated, message)
	} else {
		c.Redirect(http.StatusFound, fmt.Sprintf("/thread/%d", message.ThreadID))
	}
}

func UpdateMessage(c *gin.Context) {
	messageID := c.Param("id")
	var message models.Message

	if err := DB.First(&message, messageID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Message not found"})
		return
	}

	if err := c.ShouldBindJSON(&message); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := DB.Save(&message).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not update message"})
		return
	}

	c.JSON(http.StatusOK, message)
}

func DeleteMessage(c *gin.Context) {
	messageID := c.Param("id")
	var message models.Message

	if err := DB.First(&message, messageID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Message not found"})
		return
	}

	if err := DB.Delete(&message).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not delete message"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Message deleted successfully"})
}

func VoteMessage(c *gin.Context) {
	messageID := c.Param("id")
	threadID := c.PostForm("ThreadID") // Pour rediriger vers la page du thread

	var vote models.Vote
	var existingVote models.Vote

	// Si la requête est JSON, utiliser ShouldBindJSON
	contentType := c.GetHeader("Content-Type")
	if contentType == "application/json" {
		if err := c.ShouldBindJSON(&vote); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	} else {
		// Sinon, c'est un formulaire HTML
		valueStr := c.PostForm("Value")
		value, err := strconv.Atoi(valueStr)
		if err != nil {
			if c.GetHeader("Accept") == "application/json" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid vote value"})
			} else {
				c.Redirect(http.StatusFound, "/thread/"+threadID)
			}
			return
		}
		vote.Value = value
	}

	userID, exists := c.Get("userID")
	if !exists {
		if c.GetHeader("Accept") == "application/json" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		} else {
			c.Redirect(http.StatusFound, "/login")
		}
		return
	}

	// Conversion correcte de float64 à uint
	floatID, ok := userID.(float64)
	if !ok {
		if c.GetHeader("Accept") == "application/json" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user ID format"})
		} else {
			c.Redirect(http.StatusFound, "/thread/"+threadID)
		}
		return
	}
	vote.UserID = uint(floatID)

	// Convert messageID from string to uint
	var msgIDUint uint
	if _, err := fmt.Sscanf(messageID, "%d", &msgIDUint); err != nil {
		if c.GetHeader("Accept") == "application/json" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid message ID"})
		} else {
			c.Redirect(http.StatusFound, "/thread/"+threadID)
		}
		return
	}
	vote.MessageID = msgIDUint

	// Vérifier si l'utilisateur a déjà voté pour ce message
	result := DB.Where("message_id = ? AND user_id = ?", msgIDUint, vote.UserID).First(&existingVote)

	if result.RowsAffected > 0 {
		// Si le vote existe déjà et a la même valeur, supprimer le vote (annulation)
		if existingVote.Value == vote.Value {
			if err := DB.Delete(&existingVote).Error; err != nil {
				if c.GetHeader("Accept") == "application/json" {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not remove vote"})
				} else {
					c.Redirect(http.StatusFound, "/thread/"+threadID)
				}
				return
			}

			if c.GetHeader("Accept") == "application/json" {
				c.JSON(http.StatusOK, gin.H{"message": "Vote removed"})
			} else {
				c.Redirect(http.StatusFound, "/thread/"+threadID)
			}
			return
		}

		// Si le vote existe mais avec une valeur différente, mettre à jour le vote
		existingVote.Value = vote.Value
		if err := DB.Save(&existingVote).Error; err != nil {
			if c.GetHeader("Accept") == "application/json" {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not update vote"})
			} else {
				c.Redirect(http.StatusFound, "/thread/"+threadID)
			}
			return
		}

		if c.GetHeader("Accept") == "application/json" {
			c.JSON(http.StatusOK, existingVote)
		} else {
			c.Redirect(http.StatusFound, "/thread/"+threadID)
		}
		return
	}

	// Sinon, créer un nouveau vote
	if err := DB.Create(&vote).Error; err != nil {
		if c.GetHeader("Accept") == "application/json" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not vote on message"})
		} else {
			c.Redirect(http.StatusFound, "/thread/"+threadID)
		}
		return
	}

	if c.GetHeader("Accept") == "application/json" {
		c.JSON(http.StatusCreated, vote)
	} else {
		c.Redirect(http.StatusFound, "/thread/"+threadID)
	}
}

func DeleteThread(c *gin.Context) {
	threadID := c.Param("id")
	var thread models.Thread

	if err := DB.First(&thread, threadID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Thread not found"})
		return
	}

	if err := DB.Delete(&thread).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not delete thread"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Thread deleted successfully"})
}

func GetMessageVotes(c *gin.Context) {
	messageID := c.Param("id")
	var total int64

	// Calculer le total des votes (positifs moins négatifs)
	if err := DB.Model(&models.Vote{}).
		Where("message_id = ?", messageID).
		Select("COALESCE(SUM(value), 0) as total").
		Scan(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not get votes"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"total": total})
}

func HandleMessageForm(c *gin.Context) {
	// Récupérer le token et l'ID utilisateur du contexte
	userID, exists := c.Get("userID")
	if !exists {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	// Récupérer les données du formulaire
	threadIDStr := c.PostForm("ThreadID")
	content := c.PostForm("Content")

	if threadIDStr == "" || content == "" {
		c.Redirect(http.StatusFound, "/threads")
		return
	}

	// Convertir l'ID du thread en uint
	threadID, err := strconv.Atoi(threadIDStr)
	if err != nil {
		c.Redirect(http.StatusFound, "/threads")
		return
	}

	// Créer le message
	var message models.Message
	message.ThreadID = uint(threadID)
	message.Content = content

	// Conversion de userID en uint
	floatID, ok := userID.(float64)
	if !ok {
		c.Redirect(http.StatusFound, "/threads")
		return
	}
	message.UserID = uint(floatID)

	// Enregistrer le message
	if err := DB.Create(&message).Error; err != nil {
		c.Redirect(http.StatusFound, "/threads")
		return
	}

	// Rediriger vers la page du thread
	c.Redirect(http.StatusFound, fmt.Sprintf("/thread/%d", threadID))
}
