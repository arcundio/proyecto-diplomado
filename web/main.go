package main

import (
	"fmt"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"web/config"
	"web/controllers"
	"web/middleware"
	"web/utils"
)

func main() {
	// Inicia la base de datos
	config.InitDB()

	// Define el router
	r := mux.NewRouter()

	// Rutas públicas
	r.HandleFunc("/login", controllers.Login).Methods("POST")
	r.HandleFunc("/register", controllers.CreateUser).Methods("POST")
	r.HandleFunc("/upload", controllers.UploadFileHandler).Methods("POST")
	r.HandleFunc("/sign", controllers.SignFileHandler).Methods("POST")
	r.HandleFunc("/generateKeys", controllers.GenerateKeyPairHandler).Methods("POST")
	r.HandleFunc("/verify-signature/{fileID:[0-9]+}", controllers.VerifyFileSignatureHandler).Methods("GET")

	// Rutas públicas de acceso a archivos y usuarios
	r.HandleFunc("/files/{id}", controllers.GetFilesByUserID).Methods("GET")
	r.HandleFunc("/users", controllers.GetUsers).Methods("GET")
	r.HandleFunc("/users/{id}", controllers.GetUser).Methods("GET")
	r.HandleFunc("/share-file/{fileID:[0-9]+}", controllers.ShareFileHandler).Methods("POST")
	r.HandleFunc("/shared-users", controllers.GetSharedFilesUsers).Methods("GET")
	r.HandleFunc("/shared-files/{id}", controllers.GetSharedFilesHandler).Methods("GET")
	r.HandleFunc("/file/{id}/owner", controllers.CheckFileOwner).Methods("GET")

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

	tokenString, err := utils.GenerateToken("test@example.com", 123)
	if err != nil {
		log.Fatalf("Error generating token: %v", err)
	}

	fmt.Println("Generated Token:", tokenString)

	userID, err := utils.ExtractUserIDFromJWT(tokenString)
	if err != nil {
		log.Fatalf("Error extracting user ID: %v", err)
	}

	fmt.Println("Extracted UserID:", userID)

	// Inicia el servidor
	log.Fatal(http.ListenAndServe(":8505", corsHandler))
}
