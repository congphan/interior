package controllers

import (
	"net/http"
	"strings"

	"github.com/adam-hanna/jwt-auth/jwt"

	"github.com/congphan/interior/templates"
)

// AuthController ...
type AuthController struct {
	name            string
	restrictedRoute *jwt.Auth
}

// NewAuthController ...
func NewAuthController(restrictedRoute *jwt.Auth) AuthController {
	return AuthController{
		name:            "AuthController",
		restrictedRoute: restrictedRoute,
	}
}

// Login ...
func (ctrl AuthController) Login(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		templates.RenderTemplate(w, "login", &templates.LoginPage{})

	case "POST":
		r.ParseForm()

		if strings.Join(r.Form["username"], "") == "testUser" && strings.Join(r.Form["password"], "") == "testPassword" {
			claims := jwt.ClaimsType{}
			claims.CustomClaims = make(map[string]interface{})
			claims.CustomClaims["Role"] = "user"

			err := ctrl.restrictedRoute.IssueNewTokens(w, &claims)
			if err != nil {
				http.Error(w, "Internal Server Error", 500)
				return
			}

			w.WriteHeader(http.StatusOK)

		} else {
			http.Error(w, "Unauthorized", 401)
		}

	default:
		http.Error(w, "Method Not Allowed", 405)
	}
}

// Logout ...
func (ctrl AuthController) Logout(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		err := ctrl.restrictedRoute.NullifyTokens(w, r)
		if err != nil {
			http.Error(w, "Internal server error", 500)
			return
		}

		http.Redirect(w, r, "/login", 302)

	default:
		http.Error(w, "Method Not Allowed", 405)
	}
}
