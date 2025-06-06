package controllers

import (
	"fmt" // Ajoutez cet import
	"forum-educatif/models"
	"log"
	"math/rand"
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
	var request struct {
		Username string `json:"username" binding:"required"`
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Vérifier la complexité du mot de passe
	if len(request.Password) < 12 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Le mot de passe doit contenir au moins 12 caractères"})
		return
	}

	var hasUpper, hasSpecial bool
	for _, char := range request.Password {
		if unicode.IsUpper(char) {
			hasUpper = true
		}
		if unicode.IsPunct(char) || unicode.IsSymbol(char) {
			hasSpecial = true
		}
	}

	if !hasUpper {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Le mot de passe doit contenir au moins une majuscule"})
		return
	}

	if !hasSpecial {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Le mot de passe doit contenir au moins un caractère spécial"})
		return
	}

	// Vérifier si le nom d'utilisateur existe déjà
	var existingUser models.User
	if result := DB.Where("username = ?", request.Username).First(&existingUser); result.Error == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Ce nom d'utilisateur est déjà utilisé"})
		return
	}

	// Vérifier si l'email existe déjà
	if result := DB.Where("email = ?", request.Email).First(&existingUser); result.Error == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cette adresse email est déjà utilisée"})
		return
	}

	// Créer l'utilisateur
	user := models.User{
		Username:  request.Username,
		Email:     request.Email,
		CreatedAt: time.Now(),
	}

	if err := user.HashPassword(request.Password); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur lors du hachage du mot de passe"})
		return
	}

	if err := DB.Create(&user).Error; err != nil {

		if strings.Contains(err.Error(), "Duplicate entry") {
			if strings.Contains(err.Error(), "username") {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Ce nom d'utilisateur est déjà utilisé"})
			} else if strings.Contains(err.Error(), "email") {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Cette adresse email est déjà utilisée"})
			} else {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Violation de contrainte d'unicité"})
			}
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur lors de la création de l'utilisateur"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "Utilisateur créé avec succès", "id": user.ID})
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

	// Vérifier que l'identifiant n'est pas vide
	if credentials.Identifier == "" || credentials.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "L'identifiant et le mot de passe sont requis"})
		return
	}

	var user models.User
	result := DB.Where("username = ? OR email = ?", credentials.Identifier, credentials.Identifier).First(&user)

	if result.Error != nil || user.CheckPassword(credentials.Password) != nil {

		if result.Error != nil {
			log.Printf("Échec de connexion: utilisateur non trouvé pour l'identifiant %s", credentials.Identifier)

			time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond)
		} else {
			log.Printf("Échec de connexion: mot de passe incorrect pour l'utilisateur %s", user.Username)
		}

		// Réponse générique pour le client
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Identifiant ou mot de passe incorrect"})
		return
	}

	// Create JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 24).Unix(),
		"iat": time.Now().Unix(), // Ajout de la date d'émission
	})

	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
		return
	}

	now := time.Now()
	user.LastLogin = &now
	DB.Save(&user)

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

// Fonction utilitaire pour générer un refresh token
func generateRefreshToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
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
	// Structure pour la désérialisation des données reçues
	var threadRequest struct {
		Title      string   `json:"Title"`
		Content    string   `json:"Content"`
		Tags       []string `json:"Tags"`
		CategoryID uint     `json:"CategoryID"`
	}

	if err := c.ShouldBindJSON(&threadRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Débogage : afficher le type et la valeur de userID
	fmt.Printf("Type de userID: %T, Valeur: %v\n", userID, userID)

	// Conversion correcte de float64 à uint
	floatID, ok := userID.(float64)
	if !ok {
		// Essayer de convertir à partir d'autres types possibles
		switch v := userID.(type) {
		case float64:
			floatID = v
		case int:
			floatID = float64(v)
		case int64:
			floatID = float64(v)
		case uint:
			floatID = float64(v)
		case uint64:
			floatID = float64(v)
		case string:
			var err error
			floatID, err = strconv.ParseFloat(v, 64)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user ID format"})
				return
			}
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user ID format"})
			return
		}
	}

	var user models.User
	if err := DB.First(&user, uint(floatID)).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Referenced user does not exist"})
		return
	}

	// Création du thread
	thread := models.Thread{
		Title:     threadRequest.Title,
		Content:   threadRequest.Content,
		UserID:    user.ID,
		AuthorID:  user.ID,
		Status:    "open",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Ajout de la catégorie si spécifiée
	if threadRequest.CategoryID == 0 {
		// Récupérer la première catégorie (Général)
		var defaultCategory models.Category
		if err := DB.First(&defaultCategory).Error; err != nil {
			// Si aucune catégorie n'existe, en créer une
			defaultCategory = models.Category{
				Name:        "Général",
				Description: "Discussions générales",
				CreatedAt:   time.Now(),
			}
			if err := DB.Create(&defaultCategory).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create default category"})
				return
			}
		}
		thread.CategoryID = defaultCategory.ID
	} else {
		// Vérifier si la catégorie spécifiée existe
		var category models.Category
		if err := DB.First(&category, threadRequest.CategoryID).Error; err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Specified category does not exist"})
			return
		}
		thread.CategoryID = threadRequest.CategoryID
	}

	// Traitement des tags
	var tags []models.Tag
	for _, tagName := range threadRequest.Tags {
		if tagName == "" {
			continue // Ignorer les tags vides
		}

		// Rechercher si le tag existe déjà
		var tag models.Tag
		result := DB.Where("name = ?", tagName).First(&tag)

		if result.Error != nil {
			// Si le tag n'existe pas, on le crée
			tag = models.Tag{
				Name:      tagName,
				CreatedAt: time.Now(),
			}
			if err := DB.Create(&tag).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create tag"})
				return
			}
		}

		tags = append(tags, tag)
	}

	// Transaction pour s'assurer que tout est enregistré correctement
	err := DB.Transaction(func(tx *gorm.DB) error {
		// Créer le thread
		if err := tx.Create(&thread).Error; err != nil {
			return err
		}

		// Associer les tags au thread
		if len(tags) > 0 {
			if err := tx.Model(&thread).Association("Tags").Append(tags); err != nil {
				return err
			}
		}

		return nil
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create thread: " + err.Error()})
		return
	}

	// Charger les tags pour la réponse
	DB.Model(&thread).Association("Tags").Find(&thread.Tags)

	c.JSON(http.StatusCreated, thread)
}

func GetCategories(c *gin.Context) {
	var categories []models.Category
	if err := DB.Find(&categories).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not retrieve categories"})
		return
	}

	c.JSON(http.StatusOK, categories)
}

func GetThread(c *gin.Context) {
	threadID := c.Param("id")
	var thread models.Thread

	// Récupérer le paramètre de tri
	sortBy := c.DefaultQuery("sort", "recent") // Par défaut, tri par date

	// Charger le thread avec ses messages
	if err := DB.Preload("User").Where("id = ? AND status != ?", threadID, "archived").First(&thread).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not retrieve thread"})
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
	var thread models.Thread
	if err := DB.First(&thread, message.ThreadID).Error; err != nil {
		// Gérer l'erreur
		return
	}

	if thread.Status != "open" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Ce fil de discussion est fermé ou archivé"})
		return
	}
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

	// Récupérer d'abord le threadID associé au message
	var message models.Message
	if err := DB.First(&message, messageID).Error; err != nil {
		if c.GetHeader("Accept") == "application/json" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Message not found"})
		} else {
			c.Redirect(http.StatusFound, "/threads") // Rediriger vers la liste des threads en cas d'erreur
		}
		return
	}

	// Maintenant nous avons le threadID correct du message
	threadID := strconv.Itoa(int(message.ThreadID))

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
				c.Redirect(http.StatusFound, "/threads")
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
			c.Redirect(http.StatusFound, "/threads")
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
			c.Redirect(http.StatusFound, "/threads")
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
					c.Redirect(http.StatusFound, "/threads")
				}
				return
			}

			if c.GetHeader("Accept") == "application/json" {
				c.JSON(http.StatusOK, gin.H{"message": "Vote removed"})
			} else {
				// Utiliser la route correcte
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
				c.Redirect(http.StatusFound, "/threads")
			}
			return
		}

		if c.GetHeader("Accept") == "application/json" {
			c.JSON(http.StatusOK, existingVote)
		} else {
			// Utiliser la route correcte
			c.Redirect(http.StatusFound, "/thread/"+threadID)
		}
		return
	}

	// Sinon, créer un nouveau vote
	if err := DB.Create(&vote).Error; err != nil {
		if c.GetHeader("Accept") == "application/json" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not vote on message"})
		} else {
			c.Redirect(http.StatusFound, "/threads")
		}
		return
	}

	if c.GetHeader("Accept") == "application/json" {
		c.JSON(http.StatusCreated, vote)
	} else {
		// Utiliser la route correcte
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
