package main

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/congphan/interior/templates"

	"github.com/adam-hanna/jwt-auth/jwt"
	"goji.io"
	"goji.io/pat"
)

var restrictedRoute jwt.Auth

var myUnauthorizedHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "I Pitty the fool who is Unauthorized", 401)
	return
})

var restrictedHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	csrfSecret := w.Header().Get("X-CSRF-Token")
	claims, err := restrictedRoute.GrabTokenClaims(r)
	if err != nil {
		http.Error(w, "Internal Server Error", 500)
		return
	}

	templates.RenderTemplate(w, "restricted", &templates.RestrictedPage{csrfSecret, claims.CustomClaims["Role"].(string)})
})

var loginHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		templates.RenderTemplate(w, "login", &templates.LoginPage{})

	case "POST":
		r.ParseForm()

		if strings.Join(r.Form["username"], "") == "testUser" && strings.Join(r.Form["password"], "") == "testPassword" {
			claims := jwt.ClaimsType{}
			claims.CustomClaims = make(map[string]interface{})
			claims.CustomClaims["Role"] = "user"

			err := restrictedRoute.IssueNewTokens(w, &claims)
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
})

var logoutHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		err := restrictedRoute.NullifyTokens(w, r)
		if err != nil {
			http.Error(w, "Internal server error", 500)
			return
		}

		http.Redirect(w, r, "/login", 302)

	default:
		http.Error(w, "Method Not Allowed", 405)
	}
})

func main() {
	authErr := jwt.New(&restrictedRoute, jwt.Options{
		SigningMethodString:   "RS256",
		PrivateKeyLocation:    "keys/app.rsa",     // `$ openssl genrsa -out app.rsa 2048`
		PublicKeyLocation:     "keys/app.rsa.pub", // `$ openssl rsa -in app.rsa -pubout > app.rsa.pub`
		RefreshTokenValidTime: 72 * time.Hour,
		AuthTokenValidTime:    1 * time.Second,
		Debug:                 true,
		IsDevEnv:              true,
	})
	if authErr != nil {
		log.Println("Error initializing the JWT's!")
		log.Fatal(authErr)
	}

	restrictedRoute.SetUnauthorizedHandler(myUnauthorizedHandler)

	mux := goji.NewMux()

	mux.HandleFunc(pat.New("/login"), loginHandler)

	// this will never be available because we never issue tokens
	// see login_logout example for how to provide tokens
	mux.Handle(pat.New("/restricted"), restrictedRoute.Handler(restrictedHandler))

	// logout
	mux.Handle(pat.New("/logout"), restrictedRoute.Handler(logoutHandler))

	//	mux.Use(restrictedRoute.Handler)
	http.ListenAndServe("localhost:8000", mux)
}
