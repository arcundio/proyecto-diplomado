package models

import (
    "gorm.io/gorm"
)

type File struct {
    ID        uint      `gorm:"primaryKey"`
    UserID    uint      `gorm:"not null"`
    FileName  string    `gorm:"type:varchar(255);not null"`
    FileData  []byte    `gorm:"type:bytea;not null"`
    FileHash  string    `gorm:"type:text;not null"`
    HashAlg   string    `gorm:"type:varchar(255)"`
    FileSize  string    `gorm:"type:varchar(255)"`
}

type User struct {
    gorm.Model
    Email    string `gorm:"unique" json:"email"`
    Passwrd string `json:"passwrd"`
}

// Estructura del JSON
type UploadFileRequest struct {
    UserID    uint   `json:"userid"`
    FileName  string `json:"filename"`
    FileData  string `json:"fileData"`
    FileSize  string `json:"fileSize"`
}

type SignFileRequest struct {
    UserID      uint   `json:"userId"`
    FileID      uint   `json:"fileId"`
    PrivateKey  string `json:"privateKey"`
}

type VerifySignatureRequest struct {
    FileID      uint   `json:"fileId"`
    Signature   string `json:"signature"`
    PublicKey   string `json:"publicKey"`
}

type Signature struct {
    ID        uint           `gorm:"primaryKey" json:"id"`
    FileID    uint           `gorm:"not null" json:"fileId"`
    UserID    uint           `gorm:"not null" json:"userId"`
    Signature string         `gorm:"type:text;not null" json:"signature"`
}

type GenerateKeyPairRequest struct {
    UserID uint `json:"userId"`
}

// PublicKey representa la estructura de una llave pública en la base de datos
type PublicKey struct {
    ID        uint   `json:"id" gorm:"primaryKey"`
    UserID    uint   `json:"userId"`  // Llave foránea para el ID del usuario
    PublicKey string `json:"publicKey"`     // Llave pública en formato PEM
}