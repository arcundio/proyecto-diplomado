package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"web/config"
	"web/controllers"
	"web/middleware"
	"web/models"
	"web/utils"
)

var (
	oauth2Config *oauth2.Config
	stateToken   = "random_state_string" // Debes usar un valor aleatorio y seguro en producción
)

func main() {
	// Inicia la base de datos
	config.InitDB()

	// Inicializa la configuración de OAuth2
	initOAuthConfig()

	// Define el router
	r := mux.NewRouter()

	// Rutas públicas
	r.HandleFunc("/api/login", controllers.Login).Methods("POST")
	r.HandleFunc("/api/register", controllers.CreateUser).Methods("POST")
	r.HandleFunc("/api/upload", controllers.UploadFileHandler).Methods("POST")
	r.HandleFunc("/api/sign", controllers.SignFileHandler).Methods("POST")
	r.HandleFunc("/api/generateKeys", controllers.GenerateKeyPairHandler).Methods("POST")
	r.HandleFunc("/api/verify-signature", controllers.VerifySignature).Methods("POST")

	// Rutas públicas de acceso a archivos y usuarios
	r.HandleFunc("/api/files/{id}", controllers.GetFilesByUserID).Methods("GET")
	r.HandleFunc("/api/users", controllers.GetUsers).Methods("GET")
	r.HandleFunc("/api/users/{id}", controllers.GetUser).Methods("GET")
	r.HandleFunc("/api/share-file/{fileID:[0-9]+}", controllers.ShareFileHandler).Methods("POST")
	r.HandleFunc("/api/shared-users", controllers.GetSharedFilesUsers).Methods("GET")
	r.HandleFunc("/api/shared-files/{id}", controllers.GetSharedFilesHandler).Methods("GET")
	r.HandleFunc("/api/file/{id}/owner", controllers.CheckFileOwner).Methods("GET")

	// Ruta para iniciar el proceso de login con Google OAuth2
	r.HandleFunc("/api/auth/google", googleLoginHandler).Methods("GET")

	// Ruta para manejar el callback/redirección de Google
	r.HandleFunc("/api/auth/google/callback", googleCallbackHandler).Methods("GET")


	// Rutas protegidas
	protected := r.PathPrefix("/").Subrouter()
	protected.Use(middleware.AuthMiddleware)

	// Ejemplo de rutas protegidas
	protected.HandleFunc("/users/{id}", controllers.UpdateUser).Methods("PUT")
	protected.HandleFunc("/users/{id}", controllers.DeleteUser).Methods("DELETE")

	// Configurar CORS
	corsHandler := handlers.CORS(
		handlers.AllowedOrigins([]string{"*"}),                                       // Permitir todas las orígenes
		handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}), // Permitir estos métodos
		handlers.AllowedHeaders([]string{"Content-Type", "Authorization"}),           // Permitir estos encabezados
	)(r)

	// Inicia el servidor (Traefik manejará HTTPS)
	log.Fatal(http.ListenAndServe(":8505", corsHandler))
}

// Inicializa la configuración OAuth2 con los parámetros de Google
func initOAuthConfig() {
	oauth2Config = &oauth2.Config{
		ClientID:     "1037996082378-lnaa024kcgajn3d3p866oqbd49om8b82.apps.googleusercontent.com", // Reemplazar con tu ClientID
		ClientSecret: "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", // Reemplazar con tu ClientSecret
		RedirectURL:  "https://www.nomcci.top/api/auth/google/callback", // URL configurada en Google Cloud
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"}, // Scopes de Google
		Endpoint:     google.Endpoint, // Usar el endpoint de Google
	}
}

// Controlador para redirigir al usuario a la página de autenticación de Google
func googleLoginHandler(w http.ResponseWriter, r *http.Request) {
	url := oauth2Config.AuthCodeURL(stateToken)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// Controlador para manejar la redirección/callback de Google
func googleCallbackHandler(w http.ResponseWriter, r *http.Request) {
	// Verificar si el estado es válido
	if r.FormValue("state") != stateToken {
		http.Error(w, "Estado inválido", http.StatusBadRequest)
		return
	}

	// Obtener el código de autorización
	code := r.FormValue("code")
	if code == "" {
		http.Error(w, "Código no encontrado", http.StatusBadRequest)
		return
	}

	// Intercambiar el código por un token
	token, err := oauth2Config.Exchange(context.TODO(), code)
	if err != nil {
		http.Error(w, "No se pudo intercambiar el código por el token", http.StatusInternalServerError)
		return
	}

	// Crear un cliente autenticado con el token
	client := oauth2Config.Client(context.TODO(), token)

	// Llamar a una API de Google como ejemplo (opcional)
	email, err := getUserEmail(client)
	if err != nil {
		http.Error(w, "No se pudo obtener el email del usuario", http.StatusInternalServerError)
		return
	}

	var existingUser models.User
	result := config.DB.Where("email = ?", email).First(&existingUser)
	if result.Error == nil {
		// existe el correo
		// Generar el token con el UserID
		token, err := utils.GenerateToken(existingUser.Email, existingUser.UserID)
		if err != nil {
			http.Error(w, "Could not generate token", http.StatusInternalServerError)
			return
		}

		redirectURL := fmt.Sprintf("https://www.nomcci.top/login-success?token=%s&userID=%d", token, existingUser.UserID)
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)

	} else {
		// no existe el correo
		var user models.User
		user.Email = email

		password, err := generateRandomString(16)
		if err != nil {
			fmt.Println("Error generando la cadena:", err)
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Could not hash password", http.StatusInternalServerError)
			return
		}
		user.Passwrd = string(hashedPassword)

		// Guardar el nuevo usuario en la base de datos
		if result := config.DB.Create(&user); result.Error != nil {
			http.Error(w, "Could not create user", http.StatusInternalServerError)
			return
		}

		token, err := utils.GenerateToken(user.Email, user.UserID)
		if err != nil {
			http.Error(w, "Could not generate token", http.StatusInternalServerError)
			return
		}

		redirectURL := fmt.Sprintf("https://nomcci.top/login-success?token=%s&userID=%d", token, user.UserID)
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
	}
}

// Función para obtener el email del usuario autenticado usando la API de Google
func getUserEmail(client *http.Client) (string, error) {
	// Se puede hacer una solicitud a "https://www.googleapis.com/oauth2/v2/userinfo?alt=json" para obtener los datos del usuario
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo?alt=json")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Extraer el email del cuerpo de la respuesta
	var userInfo struct {
		Email string `json:"email"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return "", err
	}

	return userInfo.Email, nil
}

// Genera una cadena aleatoria de longitud especificada
func generateRandomString(length int) (string, error) {
	// Genera una secuencia de bytes aleatorios
	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	// Codifica los bytes aleatorios en una cadena segura usando base64
	return base64.URLEncoding.EncodeToString(randomBytes)[:length], nil
}
