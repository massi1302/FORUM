package routes

import (
	"fmt"
	"forum-educatif/controllers"
	"forum-educatif/database"
	"forum-educatif/middlewares"
	"forum-educatif/models"
	"math"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
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
		isLoggedIn, _ := c.Get("isLoggedIn")
		if isLoggedIn.(bool) {
			c.Redirect(http.StatusFound, "/")
			return
		}

		c.HTML(http.StatusOK, "login.html", gin.H{
			"title":      "Connexion",
			"isLoggedIn": false,
		})
	})

	r.GET("/register", func(c *gin.Context) {
		isLoggedIn, _ := c.Get("isLoggedIn")
		if isLoggedIn.(bool) {
			c.Redirect(http.StatusFound, "/")
			return
		}

		c.HTML(http.StatusOK, "register.html", gin.H{
			"title":      "Inscription",
			"isLoggedIn": false,
		})
	})

	r.GET("/threads", func(c *gin.Context) {
		token, _ := c.Get("token")
		isLoggedIn, _ := c.Get("isLoggedIn")
		var categories []models.Category
		if err := database.DB.Find(&categories).Error; err != nil {
			// En cas d'erreur, continuer avec une liste vide de catégories
			categories = []models.Category{}
		}

		c.HTML(http.StatusOK, "threads.html", gin.H{
			"title":      "Tous les sujets",
			"token":      token,
			"isLoggedIn": isLoggedIn,
			"categories": categories,
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
	r.GET("/profile", func(c *gin.Context) {
		token, _ := c.Get("token")
		userID, exists := c.Get("userID")

		c.HTML(http.StatusOK, "profile.html", gin.H{
			"title":      "Mon profil",
			"token":      token,
			"isLoggedIn": exists,
			"userID":     userID,
		})
	})

	// API routes
	api := r.Group("/api")
	{
		// Auth routes
		auth := api.Group("/auth")
		{
			auth.POST("/register", controllers.Register)
			auth.POST("/login", controllers.Login)
			//			auth.POST("/logout", controllers.Logout)
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

	return r
}
