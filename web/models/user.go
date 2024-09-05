package models

type File struct {
	ID       uint   `gorm:"primaryKey"`
	UserID   int    `gorm:"not null"`
	FileName string `gorm:"type:varchar(255);not null"`
	FileData []byte `gorm:"type:bytea;not null"`
	FileHash string `gorm:"type:text;not null"`
	HashAlg  string `gorm:"type:varchar(255)"`
	FileSize string `gorm:"type:varchar(255)"`
}

type User struct {
	UserID  int    `json:"id" gorm:"primaryKey;autoIncrement"`
	Email   string `gorm:"unique" json:"email"`
	Passwrd string `json:"passwrd"`
}

type UserDTO struct {
	UserID int    `gorm:"column:id; json:"id"`
	Email  string `gorm:"unique" json:"email"`
}

// Estructura del JSON
type UploadFileRequest struct {
	UserID   uint   `json:"userid"`
	FileName string `json:"filename"`
	FileData string `json:"fileData"`
	FileSize string `json:"fileSize"`
}

type SignFileRequest struct {
	UserID     uint   `json:"userId"`
	FileID     uint   `json:"fileId"`
	PrivateKey string `json:"privateKey"`
}

type VerifySignatureRequest struct {
	FileID    uint   `json:"fileId"`
	Signature string `json:"signature"`
	PublicKey string `json:"publicKey"`
}

type Signatures struct {
	ID            int    `gorm:"primaryKey" json:"id"`
	FileID        int    `gorm:"not null" json:"fileId"`
	UserID        int    `gorm:"not null" json:"userId"`
	FileSignature string `gorm:"type:text;not null" json:"signature"`
}

type UserReq struct {
	UserID  int    `json:"userId"`
	KeyName string `json:"keyName"`
}

type VerifyUserReq struct {
	UserID int `json:"userId"`
	FileID int `json:"fileId"`
}

// PublicKey representa la estructura de una llave pública en la base de datos
type PublicKey struct {
	ID        uint   `json:"id" gorm:"primaryKey"`
	UserID    int    `json:"userId"`    // Llave foránea para el ID del usuario
	PublicKey string `json:"publicKey"` // Llave pública en formato PEM
	KeyName   string `json:"keyName"`
}

type SharedFile struct {
	ID           int `json:"id"`
	IDUser       int `json:"id_user"`
	IDUserShared int `json:"id_user_shared"`
	IDFile       int `json:"id_file"`
}
