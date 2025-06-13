package routes

import (
	"html/template"
	"time"
)

// TemplateFuncs est un map des fonctions utilitaires à utiliser dans les templates
var TemplateFuncs = template.FuncMap{
	"add": func(a, b int) int {
		return a + b
	},
	"sub": func(a, b int) int { // Fonction "sub" manquante
		return a - b
	},
	"mul": func(a, b int) int {
		return a * b
	},
	"div": func(a, b int) int {
		if b == 0 {
			return 0
		}
		return a / b
	},
	"eq": func(a, b interface{}) bool {
		return a == b
	},
	"seq": func(start, end int) []int {
		var result []int
		for i := start; i <= end; i++ {
			result = append(result, i)
		}
		return result
	},
	"formatDate": func(t time.Time) string {
		return t.Format("02/01/2006 à 15:04")
	},
	// Ajouter également une fonction truncate pour tronquer le texte
	"truncate": func(s string, l int) string {
		if len(s) > l {
			return s[:l] + "..."
		}
		return s
	},
}
