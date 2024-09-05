package config

import (
	"fmt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"log"
	"os"
	"web/models"
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
	DB.AutoMigrate(&models.File{})
	DB.AutoMigrate(&models.SharedFile{})

	// Obtener todos los archivos compartidos
	var sharedFiles []models.SharedFile
	result := DB.Table("shared").Find(&sharedFiles)
	if result.Error != nil {
		log.Println("Error retrieving shared files:", result.Error)
	} else {
		log.Println("Shared Files:")
		for _, sharedFile := range sharedFiles {
			log.Printf("ID: %d, IDUser: %d, IDUserShared: %d, IDFile: %d\n", sharedFile.ID, sharedFile.IDUser, sharedFile.IDUserShared, sharedFile.IDFile)
		}
	}
}
