package main

import (
	"log"
	"net/http"
	"time"

	"github.com/adam-hanna/jwt-auth/jwt"
	"goji.io"
	"goji.io/pat"

	"github.com/congphan/interior/controllers"
	"github.com/congphan/interior/templates"
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

	authCtrl := controllers.NewAuthController(&restrictedRoute)
	mux.HandleFunc(pat.New("/login"), authCtrl.Login)

	// this will never be available because we never issue tokens
	// see login_logout example for how to provide tokens
	mux.Handle(pat.New("/restricted"), restrictedRoute.Handler(restrictedHandler))

	// logout
	mux.HandleFunc(pat.New("/logout"), authCtrl.Logout)

	//	mux.Use(restrictedRoute.Handler)
	http.ListenAndServe("localhost:8000", mux)
}
