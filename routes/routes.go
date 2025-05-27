package routes

import (
	"forum-educatif/controllers"
	"forum-educatif/middlewares"
	"net/http"

	"github.com/gin-gonic/gin"
)

func SetupRoutes() *gin.Engine {
	r := gin.Default()

	// Servir les fichiers statiques
	r.Static("/static", "./static")

	// Charger les templates HTML
	r.LoadHTMLGlob("templates/*")

	// Routes pour les pages HTML
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{
			"title": "Forum Éducatif - Accueil",
		})
	})

	r.GET("/login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", gin.H{
			"title": "Connexion",
		})
	})

	r.GET("/register", func(c *gin.Context) {
		c.HTML(http.StatusOK, "register.html", gin.H{
			"title": "Inscription",
		})
	})

	r.GET("/threads", func(c *gin.Context) {
		c.HTML(http.StatusOK, "threads.html", gin.H{
			"title": "Tous les sujets",
		})
	})

	r.GET("/thread/:id", func(c *gin.Context) {
		id := c.Param("id")
		c.HTML(http.StatusOK, "thread_detail.html", gin.H{
			"title": "Détail du sujet",
			"id":    id,
		})
	})

	r.GET("/profile", func(c *gin.Context) {
		c.HTML(http.StatusOK, "profile.html", gin.H{
			"title": "Mon profil",
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

	return r
}
