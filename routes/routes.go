package routes

import (
	"fmt"
	"forum-educatif/controllers"
	"forum-educatif/database"
	"forum-educatif/middlewares"
	"forum-educatif/models"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

func SetupRoutes(r *gin.Engine) *gin.Engine {

	// Servir les fichiers statiques
	r.Static("/static", "./static")

	r.SetFuncMap(TemplateFuncs)

	// Charger les templates HTML
	r.LoadHTMLGlob("templates/*")

	r.Use(middlewares.SetUserAuthInfo())

	// Routes pour les pages HTML
	r.GET("/", func(c *gin.Context) {
		token, _ := c.Get("token")
		isLoggedIn, _ := c.Get("isLoggedIn")

		c.HTML(http.StatusOK, "index.html", gin.H{
			"title":      "Forum Éducatif - Accueil",
			"token":      token,
			"isLoggedIn": isLoggedIn,
		})
	})

	r.GET("/login", func(c *gin.Context) {
		// Vérifier si l'utilisateur est déjà connecté
		isLoggedIn, _ := c.Get("isLoggedIn")
		if isLoggedIn.(bool) {
			c.Redirect(http.StatusFound, "/")
			return
		}

		// Récupérer les messages de l'URL
		errorMsg := c.Query("error")
		registered := c.Query("registered")

		c.HTML(http.StatusOK, "login.html", gin.H{
			"title":      "Connexion",
			"error":      errorMsg,
			"registered": registered,
		})
	})

	// Route pour traiter le formulaire de connexion
	r.POST("/login", func(c *gin.Context) {
		identifier := c.PostForm("identifier")
		password := c.PostForm("password")

		// Validation des entrées
		if identifier == "" || password == "" {
			c.Redirect(http.StatusFound, "/login?error=empty")
			return
		}

		// Rechercher l'utilisateur dans la base de données
		var user models.User
		result := database.DB.Where("username = ? OR email = ?", identifier, identifier).First(&user)

		if result.Error != nil {
			// Utilisateur non trouvé
			c.Redirect(http.StatusFound, "/login?error=invalid")
			return
		}

		// Vérifier le mot de passe
		err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
		if err != nil {
			// Mot de passe incorrect
			c.Redirect(http.StatusFound, "/login?error=invalid")
			return
		}

		// Mettre à jour la dernière connexion
		now := time.Now()
		user.LastLogin = &now
		database.DB.Save(&user)

		// Créer un token JWT
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": user.ID,
			"exp": time.Now().Add(time.Hour * 24 * 7).Unix(), // 7 jours
		})

		tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
		if err != nil {
			c.Redirect(http.StatusFound, "/login?error=server")
			return
		}

		// Définir le cookie d'authentification
		c.SetCookie("token", tokenString, 3600*24*7, "/", "", false, true)

		// Rediriger vers la page d'accueil
		c.Redirect(http.StatusFound, "/")
	})

	r.GET("/register", func(c *gin.Context) {
		// Vérifier si l'utilisateur est déjà connecté
		isLoggedIn, _ := c.Get("isLoggedIn")
		if isLoggedIn.(bool) {
			c.Redirect(http.StatusFound, "/")
			return
		}

		// Récupérer le message d'erreur s'il existe
		errorMsg := c.Query("error")

		c.HTML(http.StatusOK, "register.html", gin.H{
			"title": "Inscription",
			"error": errorMsg,
		})
	})

	r.POST("/register", func(c *gin.Context) {
		username := c.PostForm("username")
		email := c.PostForm("email")
		password := c.PostForm("password")
		passwordConfirm := c.PostForm("password_confirm")

		// Validation des entrées
		if username == "" || email == "" || password == "" || passwordConfirm == "" {
			c.Redirect(http.StatusFound, "/register?error=empty")
			return
		}

		if password != passwordConfirm {
			c.Redirect(http.StatusFound, "/register?error=password_match")
			return
		}

		if len(password) < 8 {
			c.Redirect(http.StatusFound, "/register?error=password_short")
			return
		}

		// Vérifier si l'email est déjà utilisé
		var existingUser models.User
		if err := database.DB.Where("email = ?", email).First(&existingUser).Error; err == nil {
			c.Redirect(http.StatusFound, "/register?error=email_exists")
			return
		}

		// Vérifier si le nom d'utilisateur est déjà utilisé
		if err := database.DB.Where("username = ?", username).First(&existingUser).Error; err == nil {
			c.Redirect(http.StatusFound, "/register?error=username_exists")
			return
		}

		// Hasher le mot de passe
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			c.Redirect(http.StatusFound, "/register?error=server")
			return
		}

		// Créer l'utilisateur
		user := models.User{
			Username:  username,
			Email:     email,
			Password:  string(hashedPassword),
			Role:      "user",
			CreatedAt: time.Now(),
		}

		if err := database.DB.Create(&user).Error; err != nil {
			c.Redirect(http.StatusFound, "/register?error=server")
			return
		}

		// Rediriger vers la page de connexion avec un message de succès
		c.Redirect(http.StatusFound, "/login?registered=true")
	})

	r.GET("/threads", func(c *gin.Context) {
		// Récupérer les informations d'authentification
		isLoggedIn, exists := c.Get("isLoggedIn")
		if !exists {
			isLoggedIn = false
		}

		// Récupérer les paramètres de requête
		userIDStr := c.Query("user")
		categoryIDStr := c.Query("category")
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		pageSize, _ := strconv.Atoi(c.DefaultQuery("size", "10"))

		// Log pour débogage
		fmt.Printf("Requête de threads - User: %s, Category: %s, Page: %d, Size: %d\n",
			userIDStr, categoryIDStr, page, pageSize)

		// Si on veut les threads d'un utilisateur spécifique
		if userIDStr != "" {
			// Traitement des threads d'un utilisateur spécifique
			// ...
			return
		}

		// Requête de base pour tous les threads
		db := database.DB.Model(&models.Thread{})

		// Filtrer par catégorie si spécifiée
		if categoryIDStr != "" {
			db = db.Where("category_id = ?", categoryIDStr)
		}

		// Compter le nombre total de threads
		var total int64
		if err := db.Count(&total).Error; err != nil {
			fmt.Printf("Erreur lors du comptage des threads: %v\n", err)
			total = 0
		}

		fmt.Printf("Nombre total de threads: %d\n", total)

		// Calculer le nombre total de pages
		totalPages := int(math.Ceil(float64(total) / float64(pageSize)))
		if page < 1 {
			page = 1
		}
		if page > totalPages && totalPages > 0 {
			page = totalPages
		}

		// Offset pour la pagination
		offset := (page - 1) * pageSize

		// Récupérer les threads avec pagination
		var threads []models.Thread
		result := db.Order("created_at DESC").
			Preload("User").
			Preload("Category").
			Limit(pageSize).
			Offset(offset).
			Find(&threads)

		if result.Error != nil {
			fmt.Printf("Erreur lors de la récupération des threads: %v\n", result.Error)
		}

		fmt.Printf("Nombre de threads récupérés: %d\n", len(threads))

		// Récupérer toutes les catégories pour le filtre
		var categories []models.Category
		if err := database.DB.Find(&categories).Error; err != nil {
			fmt.Printf("Erreur lors de la récupération des catégories: %v\n", err)
		}

		// Afficher la page threads.html
		c.HTML(http.StatusOK, "threads.html", gin.H{
			"title":      "Tous les sujets",
			"threads":    threads,
			"categories": categories,
			"categoryID": categoryIDStr,
			"isLoggedIn": isLoggedIn,
			"page":       page,
			"pageSize":   pageSize,
			"totalPages": totalPages,
			"total":      total,
		})
	})
	r.GET("/thread/:id", func(c *gin.Context) {
		id := c.Param("id")
		sortBy := c.DefaultQuery("sort", "recent") // Par défaut, tri par date
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		pageSize, _ := strconv.Atoi(c.DefaultQuery("size", "10")) // 10 messages par page par défaut
		_, isAdmin := c.Get("isAdmin")
		token, _ := c.Get("token")
		_, isLoggedIn := c.Get("userID")

		// Récupérer les détails du thread
		var thread models.Thread
		if err := database.DB.Preload("User").First(&thread, id).Error; err != nil {
			c.HTML(http.StatusNotFound, "error.html", gin.H{
				"title":      "Erreur",
				"message":    "Thread introuvable",
				"token":      token,
				"isLoggedIn": isLoggedIn,
				"isAdmin":    isAdmin,
			})
			return
		}

		// Compter le nombre total de messages pour la pagination
		var total int64
		database.DB.Model(&models.Message{}).Where("thread_id = ?", id).Count(&total)

		// Calculer le nombre total de pages
		totalPages := int(math.Ceil(float64(total) / float64(pageSize)))
		if page < 1 {
			page = 1
		}
		if page > totalPages && totalPages > 0 {
			page = totalPages
		}

		// Offset pour la pagination
		offset := (page - 1) * pageSize

		// Charger les messages selon le tri demandé
		var messages []models.Message

		if sortBy == "popular" {
			database.DB.Model(&models.Message{}).
				Select("messages.*, COALESCE(SUM(votes.value), 0) as vote_count").
				Joins("LEFT JOIN votes ON votes.message_id = messages.id").
				Where("messages.thread_id = ?", id).
				Group("messages.id").
				Order("vote_count DESC").
				Preload("User").
				Limit(pageSize).
				Offset(offset).
				Find(&messages)
		} else {
			database.DB.Where("thread_id = ?", id).
				Order("created_at DESC").
				Preload("User").
				Limit(pageSize).
				Offset(offset).
				Find(&messages)
		}

		// Assigner les messages au thread
		thread.Messages = messages

		// Récupérer les votes pour chaque message
		for i := range thread.Messages {
			var voteCount int64
			database.DB.Model(&models.Vote{}).
				Where("message_id = ?", thread.Messages[i].ID).
				Select("COALESCE(SUM(value), 0) as total").
				Scan(&voteCount)
			thread.Messages[i].VoteCount = int(voteCount)
		}

		c.HTML(http.StatusOK, "thread_detail.html", gin.H{
			"title":      thread.Title,
			"thread":     thread,
			"id":         id,
			"token":      token,
			"sortBy":     sortBy,
			"isLoggedIn": isLoggedIn,
			"page":       page,
			"pageSize":   pageSize,
			"totalPages": totalPages,
			"total":      total,
			"isAdmin":    isAdmin,
		})
	})
	// Route pour afficher les détails du profil
	r.GET("/profile", func(c *gin.Context) {
		isLoggedIn, _ := c.Get("isLoggedIn")
		if !isLoggedIn.(bool) {
			c.Redirect(http.StatusFound, "/login")
			return
		}

		userID, exists := c.Get("userID")
		if !exists {
			c.Redirect(http.StatusFound, "/login")
			return
		}

		// Convertir userID en uint selon son type
		var userIDUint uint
		switch v := userID.(type) {
		case float64:
			userIDUint = uint(v)
		case uint:
			userIDUint = v
		case int:
			userIDUint = uint(v)
		default:
			fmt.Printf("Type d'ID utilisateur non géré: %T\n", userID)
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"title":      "Erreur",
				"message":    "Type d'ID utilisateur invalide",
				"isLoggedIn": true,
			})
			return
		}

		// Log pour débogage
		fmt.Printf("Recherche de l'utilisateur avec ID: %d\n", userIDUint)

		// Récupérer les données de l'utilisateur
		var user models.User
		if err := database.DB.First(&user, userIDUint).Error; err != nil {
			fmt.Printf("Erreur lors de la recherche de l'utilisateur: %v\n", err)

			// Créer un utilisateur test en mode développement
			if os.Getenv("APP_ENV") == "development" || os.Getenv("APP_ENV") == "" {
				fmt.Println("Création d'un utilisateur test...")
				user = models.User{
					ID:        userIDUint,
					Username:  "User" + strconv.Itoa(int(userIDUint)),
					Email:     "user" + strconv.Itoa(int(userIDUint)) + "@example.com",
					Role:      "user",
					CreatedAt: time.Now(),
				}

				// Hasher un mot de passe par défaut
				hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
				user.Password = string(hashedPassword)

				if err := database.DB.Create(&user).Error; err != nil {
					fmt.Printf("Erreur lors de la création de l'utilisateur test: %v\n", err)
					c.HTML(http.StatusInternalServerError, "error.html", gin.H{
						"title":      "Erreur",
						"message":    "Impossible de créer l'utilisateur",
						"isLoggedIn": true,
					})
					return
				}
				fmt.Printf("Utilisateur test créé avec ID: %d\n", user.ID)
			} else {
				c.HTML(http.StatusInternalServerError, "error.html", gin.H{
					"title":      "Erreur",
					"message":    "Utilisateur non trouvé",
					"isLoggedIn": true,
				})
				return
			}
		}

		// Compter les sujets de l'utilisateur
		var threadCount int64
		database.DB.Model(&models.Thread{}).Where("user_id = ?", userIDUint).Count(&threadCount)

		// Compter les messages de l'utilisateur
		var messageCount int64
		database.DB.Model(&models.Message{}).Where("user_id = ?", userIDUint).Count(&messageCount)

		// Récupérer les sujets de l'utilisateur
		var threads []models.Thread
		if err := database.DB.Where("user_id = ?", userIDUint).
			Order("created_at DESC").
			Limit(5).
			Find(&threads).Error; err != nil {
			fmt.Printf("Erreur lors de la récupération des threads: %v\n", err)
		}

		// Récupérer les messages de l'utilisateur
		var messages []models.Message
		if err := database.DB.Where("user_id = ?", userIDUint).
			Order("created_at DESC").
			Limit(5).
			Preload("Thread").
			Find(&messages).Error; err != nil {
			fmt.Printf("Erreur lors de la récupération des messages: %v\n", err)
		}

		// Détecter l'onglet actif
		activeTab := c.DefaultQuery("tab", "threads")

		// Détecter si une mise à jour a réussi
		success := c.Query("success") == "true"

		// Détecter les erreurs
		errorParam := c.Query("error")

		c.HTML(http.StatusOK, "profile.html", gin.H{
			"title":        "Mon profil",
			"isLoggedIn":   true,
			"user":         user,
			"threadCount":  threadCount,
			"messageCount": messageCount,
			"threads":      threads,
			"messages":     messages,
			"activeTab":    activeTab,
			"success":      success,
			"error":        errorParam,
		})
	})

	// Route pour modifier le profil
	r.POST("/profile/update", func(c *gin.Context) {
		isLoggedIn, _ := c.Get("isLoggedIn")
		if !isLoggedIn.(bool) {
			c.Redirect(http.StatusFound, "/login")
			return
		}

		userID, exists := c.Get("userID")
		if !exists {
			c.Redirect(http.StatusFound, "/login")
			return
		}

		// Convertir userID en uint
		var userIDUint uint
		switch v := userID.(type) {
		case float64:
			userIDUint = uint(v)
		case uint:
			userIDUint = v
		case int:
			userIDUint = uint(v)
		default:
			c.Redirect(http.StatusFound, "/profile?error=userid&tab=settings")
			return
		}

		// Récupérer l'utilisateur actuel
		var user models.User
		if err := database.DB.First(&user, userIDUint).Error; err != nil {
			c.Redirect(http.StatusFound, "/profile?error=notfound&tab=settings")
			return
		}

		// Récupérer les données du formulaire
		username := c.PostForm("username")
		email := c.PostForm("email")
		bio := c.PostForm("bio")
		currentPassword := c.PostForm("current_password")
		newPassword := c.PostForm("new_password")

		// Vérifier si le nom d'utilisateur ou l'email sont vides
		if username == "" || email == "" {
			c.Redirect(http.StatusFound, "/profile?error=empty&tab=settings")
			return
		}

		// Vérifier si l'utilisateur veut changer son mot de passe
		if newPassword != "" && currentPassword != "" {
			// Vérifier si le mot de passe actuel est correct
			if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(currentPassword)); err != nil {
				c.Redirect(http.StatusFound, "/profile?error=password&tab=settings")
				return
			}

			// Hasher le nouveau mot de passe
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
			if err != nil {
				c.Redirect(http.StatusFound, "/profile?error=hash&tab=settings")
				return
			}

			user.Password = string(hashedPassword)
		}

		// Mettre à jour les champs
		user.Username = username
		user.Email = email
		user.Bio = bio

		// Sauvegarder les modifications
		if err := database.DB.Save(&user).Error; err != nil {
			c.Redirect(http.StatusFound, "/profile?error=save&tab=settings")
			return
		}

		// Rediriger vers le profil avec un message de succès
		c.Redirect(http.StatusFound, "/profile?success=true&tab=settings")
	})

	// API routes
	api := r.Group("/api")
	{
		// Auth routes
		auth := api.Group("/auth")
		{
			auth.POST("/register", controllers.Register)
			auth.POST("/login", controllers.Login)
			//          auth.POST("/logout", controllers.Logout)
		}

		// Thread routes
		threads := api.Group("/threads")
		{
			threads.GET("/", controllers.GetThreads)
			threads.GET("/:id", controllers.GetThread)

			// Authenticated routes
			authRequired := threads.Group("/")
			authRequired.Use(middlewares.Auth())
			{
				authRequired.POST("/", controllers.CreateThread)
				authRequired.PUT("/:id", controllers.UpdateThread)
				authRequired.DELETE("/:id", controllers.DeleteThread)
			}
		}

		// Message routes
		messages := api.Group("/messages")
		{
			messages.GET("/:id/votes", controllers.GetMessageVotes)

			// Authenticated routes
			authRequired := messages.Group("/")
			authRequired.Use(middlewares.Auth())
			{
				authRequired.POST("/", controllers.CreateMessage)
				authRequired.PUT("/:id", controllers.UpdateMessage)
				authRequired.DELETE("/:id", controllers.DeleteMessage)
				authRequired.POST("/:id/vote", controllers.VoteMessage)
			}
		}

		// Admin routes
		admin := api.Group("/admin")
		admin.Use(middlewares.Auth(), middlewares.Admin())
		{
			admin.GET("/users", controllers.GetAllUsers)
			admin.DELETE("/users/:id", controllers.BanUser)
			admin.PUT("/threads/:id/status", controllers.ChangeThreadStatus)
		}
	}

	r.POST("/api/threads", controllers.CreateThread)

	// Route pour le formulaire de message
	r.POST("/form/message", func(c *gin.Context) {
		userID, exists := c.Get("userID")
		if !exists {
			c.Redirect(http.StatusFound, "/login")
			return
		}

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

		var message models.Message
		message.ThreadID = uint(threadID)
		message.Content = content

		floatID, ok := userID.(float64)
		if !ok {
			c.Redirect(http.StatusFound, "/threads")
			return
		}
		message.UserID = uint(floatID)

		if err := database.DB.Create(&message).Error; err != nil {
			c.Redirect(http.StatusFound, "/threads")
			return
		}

		c.Redirect(http.StatusFound, fmt.Sprintf("/thread/%d", threadID))
	})

	// Route pour afficher une catégorie spécifique
	r.GET("/category/:id", func(c *gin.Context) {
		id := c.Param("id")
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		pageSize, _ := strconv.Atoi(c.DefaultQuery("size", "10"))

		token, _ := c.Get("token")
		_, isLoggedIn := c.Get("userID")

		var category models.Category
		if err := database.DB.First(&category, id).Error; err != nil {
			c.HTML(http.StatusNotFound, "error.html", gin.H{
				"title":      "Erreur",
				"message":    "Catégorie introuvable",
				"token":      token,
				"isLoggedIn": isLoggedIn,
			})
			return
		}

		// Compter le nombre total de threads dans cette catégorie
		var total int64
		database.DB.Model(&models.Thread{}).Where("category_id = ?", id).Count(&total)

		// Calculer le nombre total de pages
		totalPages := int(math.Ceil(float64(total) / float64(pageSize)))
		if page < 1 {
			page = 1
		}
		if page > totalPages && totalPages > 0 {
			page = totalPages
		}

		// Offset pour la pagination
		offset := (page - 1) * pageSize

		var threads []models.Thread
		database.DB.Where("category_id = ?", id).
			Order("created_at DESC").
			Preload("User").
			Limit(pageSize).
			Offset(offset).
			Find(&threads)

		c.HTML(http.StatusOK, "category.html", gin.H{
			"title":      category.Name,
			"category":   category,
			"threads":    threads,
			"token":      token,
			"isLoggedIn": isLoggedIn,
			"page":       page,
			"pageSize":   pageSize,
			"totalPages": totalPages,
			"total":      total,
		})
	})

	r.GET("/tag/:id", func(c *gin.Context) {
		id := c.Param("id")
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		pageSize, _ := strconv.Atoi(c.DefaultQuery("size", "10"))

		token, _ := c.Get("token")
		_, isLoggedIn := c.Get("userID")

		var tag models.Tag
		if err := database.DB.First(&tag, id).Error; err != nil {
			c.HTML(http.StatusNotFound, "error.html", gin.H{
				"title":      "Erreur",
				"message":    "Tag introuvable",
				"token":      token,
				"isLoggedIn": isLoggedIn,
			})
			return
		}

		// Compter le nombre total de threads avec ce tag
		var total int64
		total = database.DB.Model(&tag).Association("Threads").Count()

		// Calculer le nombre total de pages
		totalPages := int(math.Ceil(float64(total) / float64(pageSize)))
		if page < 1 {
			page = 1
		}
		if page > totalPages && totalPages > 0 {
			page = totalPages
		}

		// Offset pour la pagination
		offset := (page - 1) * pageSize

		var threads []models.Thread
		database.DB.Model(&tag).
			Preload("User").
			Limit(pageSize).
			Offset(offset).
			Association("Threads").
			Find(&threads)

		c.HTML(http.StatusOK, "tag.html", gin.H{
			"title":      "Tag: " + tag.Name,
			"tag":        tag,
			"threads":    threads,
			"token":      token,
			"isLoggedIn": isLoggedIn,
			"page":       page,
			"pageSize":   pageSize,
			"totalPages": totalPages,
			"total":      total,
		})
	})

	r.GET("/search", func(c *gin.Context) {
		query := c.Query("q")
		tag := c.Query("tag")
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		pageSize, _ := strconv.Atoi(c.DefaultQuery("size", "10"))

		token, _ := c.Get("token")
		_, isLoggedIn := c.Get("userID")

		if query == "" && tag == "" {
			c.HTML(http.StatusOK, "search.html", gin.H{
				"title":      "Recherche",
				"token":      token,
				"isLoggedIn": isLoggedIn,
			})
			return
		}

		db := database.DB.Model(&models.Thread{})

		// Construire la requête de recherche
		if query != "" {
			db = db.Where("title LIKE ? OR content LIKE ?", "%"+query+"%", "%"+query+"%")
		}

		if tag != "" {
			db = db.Joins("JOIN thread_tags ON thread_tags.thread_id = threads.id").
				Joins("JOIN tags ON tags.id = thread_tags.tag_id").
				Where("tags.name = ?", tag)
		}

		// Compter le nombre total de résultats
		var total int64
		db.Count(&total)

		// Calculer le nombre total de pages
		totalPages := int(math.Ceil(float64(total) / float64(pageSize)))
		if page < 1 {
			page = 1
		}
		if page > totalPages && totalPages > 0 {
			page = totalPages
		}

		// Offset pour la pagination
		offset := (page - 1) * pageSize

		var threads []models.Thread
		db.Order("created_at DESC").
			Preload("User").
			Preload("Category").
			Preload("Tags").
			Limit(pageSize).
			Offset(offset).
			Find(&threads)

		c.HTML(http.StatusOK, "search.html", gin.H{
			"title":      "Résultats de recherche",
			"query":      query,
			"tag":        tag,
			"threads":    threads,
			"token":      token,
			"isLoggedIn": isLoggedIn,
			"page":       page,
			"pageSize":   pageSize,
			"totalPages": totalPages,
			"total":      total,
		})
	})

	r.GET("/api/categories", controllers.GetCategories)

	r.GET("/logout", func(c *gin.Context) {
		// Supprimer le cookie JWT
		c.SetCookie("token", "", -1, "/", "", false, true)

		// Rediriger vers la page d'accueil
		c.Redirect(http.StatusFound, "/")
	})

	r.POST("/threads/create", func(c *gin.Context) {
		// Vérifier si l'utilisateur est authentifié
		userID, exists := c.Get("userID")
		if !exists {
			c.Redirect(http.StatusFound, "/login")
			return
		}

		// Récupérer les données du formulaire
		title := c.PostForm("title")
		content := c.PostForm("content")
		categoryIDStr := c.PostForm("category_id")
		tagsString := c.PostForm("tags")

		// Valider les données
		if title == "" || content == "" || categoryIDStr == "" {
			c.HTML(http.StatusBadRequest, "threads.html", gin.H{
				"title":      "Créer un sujet",
				"error":      "Veuillez remplir tous les champs obligatoires",
				"isLoggedIn": true,
				"categories": GetCategories(), // Fonction pour récupérer les catégories
				// Renvoyer les données pour pré-remplir le formulaire
				"formData": gin.H{
					"title":      title,
					"content":    content,
					"categoryID": categoryIDStr,
					"tags":       tagsString,
				},
			})
			return
		}

		// Convertir categoryID en uint
		categoryID, err := strconv.ParseUint(categoryIDStr, 10, 32)
		if err != nil {
			c.HTML(http.StatusBadRequest, "threads.html", gin.H{
				"title":      "Créer un sujet",
				"error":      "Catégorie invalide",
				"isLoggedIn": true,
				"categories": GetCategories(),
				"formData": gin.H{
					"title":   title,
					"content": content,
					"tags":    tagsString,
				},
			})
			return
		}

		// Créer un nouveau thread
		thread := models.Thread{
			Title:      title,
			Content:    content,
			CategoryID: uint(categoryID),
			CreatedAt:  time.Now(),
			Status:     "active",
		}

		// Convertir userID en uint
		var threadUserID uint
		switch v := userID.(type) {
		case float64:
			threadUserID = uint(v)
		case uint:
			threadUserID = v
		case int:
			threadUserID = uint(v)
		default:
			c.HTML(http.StatusInternalServerError, "threads.html", gin.H{
				"title":      "Créer un sujet",
				"error":      "Erreur avec l'ID utilisateur",
				"isLoggedIn": true,
				"categories": GetCategories(),
				"formData": gin.H{
					"title":      title,
					"content":    content,
					"categoryID": categoryIDStr,
					"tags":       tagsString,
				},
			})
			return
		}
		thread.UserID = threadUserID

		// Sauvegarder le thread dans la base de données
		if err := database.DB.Create(&thread).Error; err != nil {
			c.HTML(http.StatusInternalServerError, "threads.html", gin.H{
				"title":      "Créer un sujet",
				"error":      "Erreur lors de la création du sujet: " + err.Error(),
				"isLoggedIn": true,
				"categories": GetCategories(),
				"formData": gin.H{
					"title":      title,
					"content":    content,
					"categoryID": categoryIDStr,
					"tags":       tagsString,
				},
			})
			return
		}

		// Traiter les tags si présents
		if tagsString != "" {
			tagNames := strings.Split(tagsString, ",")
			var threadTags []models.Tag

			for _, name := range tagNames {
				name = strings.TrimSpace(name)
				if name == "" {
					continue
				}

				// Vérifier si le tag existe déjà
				var tag models.Tag
				result := database.DB.Where("name = ?", name).First(&tag)

				if result.Error != nil {
					// Créer un nouveau tag
					tag = models.Tag{Name: name}
					if err := database.DB.Create(&tag).Error; err != nil {
						// Log l'erreur mais continuer
						log.Printf("Erreur lors de la création du tag %s: %v", name, err)
						continue
					}
				}

				threadTags = append(threadTags, tag)
			}

			// Associer les tags au thread
			if len(threadTags) > 0 {
				if err := database.DB.Model(&thread).Association("Tags").Append(threadTags); err != nil {
					// Log l'erreur mais continuer
					log.Printf("Erreur lors de l'association des tags: %v", err)
				}
			}
		}

		// Rediriger vers le nouveau thread
		c.Redirect(http.StatusFound, fmt.Sprintf("/thread/%d", thread.ID))
	})

	return r
}

// Fonction helper pour récupérer les catégories
func GetCategories() []models.Category {
	var categories []models.Category
	database.DB.Find(&categories)
	return categories
}
