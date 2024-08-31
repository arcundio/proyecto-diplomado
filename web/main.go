package main

import (
    "log"
    "net/http"
    "web/config"
    "web/controllers"
    "web/middleware"
    "github.com/gorilla/mux"
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
    r.HandleFunc("/files/{id}", controllers.GetFilesByUserID).Methods("GET")
    r.HandleFunc("/verify", controllers.VerifySignature).Methods("POST")

    // Rutas protegidas
    protected := r.PathPrefix("/").Subrouter()
    protected.Use(middleware.AuthMiddleware)
    protected.HandleFunc("/users", controllers.GetUsers).Methods("GET")
    protected.HandleFunc("/users/{id}", controllers.GetUser).Methods("GET")
    protected.HandleFunc("/users/{id}", controllers.UpdateUser).Methods("PUT")
    protected.HandleFunc("/users/{id}", controllers.DeleteUser).Methods("DELETE")

    // Inicia el servidor
    log.Fatal(http.ListenAndServe(":8505", r))
}
