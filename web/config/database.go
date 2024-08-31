package config

import (
    "fmt"
    "log"
    "gorm.io/driver/postgres"
    "gorm.io/gorm"
    "web/models"
    "os"
)

var DB *gorm.DB

func InitDB() {
    var err error
    
    // Obtén las variables de entorno para la conexión
    host := os.Getenv("DB_NAME")
    user := os.Getenv("DB_USER")
    password := os.Getenv("DB_PASSWORD")
    dbname := os.Getenv("DB_NAME")
    port := os.Getenv("DB_PORT")

    // Crear la cadena de conexión
    dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable", host, user, password, dbname, port)
    
    // Conéctate a la base de datos PostgreSQL
    DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
    if err != nil {
        log.Fatal("Failed to connect to database:", err)
    }

    // Migrar el modelo de usuario
    DB.AutoMigrate(&models.User{})
}
