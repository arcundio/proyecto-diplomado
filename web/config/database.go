package config

import (
    "fmt"
    "log"
    "gorm.io/driver/postgres"
    "gorm.io/gorm"
    "web/models"
)

var DB *gorm.DB

func InitDB() {
    var err error
    
    // Obtén las variables de entorno para la conexión
    host := "localhost"
    user := "user"
    password := "user123"
    dbname := "persistencia"
    port := "5432"

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
