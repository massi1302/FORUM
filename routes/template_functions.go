package routes

import (
	"html/template"
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
}
