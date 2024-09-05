package controllers

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"web/config"
	"web/models"
	"web/utils"
)

type Claims struct {
	UserID int `json:"user_id"`
	jwt.RegisteredClaims
}
type ShareRequest struct {
	Email  string `json:"email"`
	FileID int    `json:"fileID"`
	UserID int    `json:"userID"`
}

var jwtSecret = os.Getenv("JWT_SECRET_KEY")

// Login maneja la autenticación y genera un token JWT
func Login(w http.ResponseWriter, r *http.Request) {
	var credentials struct {
		Email   string `json:"email"`
		Passwrd string `json:"passwrd"`
	}

	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	var user models.User
	result := config.DB.Table("users").Where("email = ?", credentials.Email).First(&user)
	if result.Error != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}
	fmt.Printf("Retrieved User: %+v\n", user)

	// Verificar la contraseña
	err := bcrypt.CompareHashAndPassword([]byte(user.Passwrd), []byte(credentials.Passwrd))
	if err != nil {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	// Generar el token con el UserID
	token, err := utils.GenerateToken(user.Email, user.UserID)
	if err != nil {
		http.Error(w, "Could not generate token", http.StatusInternalServerError)
		return
	}

	// Enviar el token y el userID en la respuesta
	response := map[string]interface{}{
		"token":  token,
		"userID": user.UserID, // Agregar el userID a la respuesta
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Crear usuario
func CreateUser(w http.ResponseWriter, r *http.Request) {

	var user models.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Verificar si el email ya está registrado
	var existingUser models.User
	result := config.DB.Where("email = ?", user.Email).First(&existingUser)
	if result.Error == nil {
		http.Error(w, "Email already registered", http.StatusConflict)
		return
	}

	// Hash de la contraseña usando bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Passwrd), bcrypt.DefaultCost)
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

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
}

// Obtener todos los usuarios
func GetUsers(w http.ResponseWriter, r *http.Request) {

	var users []models.UserDTO
	config.DB.Table("users").Find(&users)
	json.NewEncoder(w).Encode(users)
}

// Obtener un usuario por ID
func GetUser(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	var user models.User
	config.DB.First(&user, params["id"])
	json.NewEncoder(w).Encode(user)
}

// Actualizar un usuario
func UpdateUser(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	var user models.User
	config.DB.First(&user, params["id"])
	json.NewDecoder(r.Body).Decode(&user)
	config.DB.Save(&user)
	json.NewEncoder(w).Encode(user)
}

// Eliminar un usuario
func DeleteUser(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	var user models.User
	config.DB.Delete(&user, params["id"])
	json.NewEncoder(w).Encode("User deleted")
}

func UploadFileHandler(w http.ResponseWriter, r *http.Request) {
	// Parsear el formulario con un límite de 10MB para los archivos
	err := r.ParseMultipartForm(10 << 20) // 10MB
	if err != nil {
		http.Error(w, "Unable to parse form", http.StatusBadRequest)
		return
	}

	// Obtener el archivo del formulario
	file, fileHeader, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Unable to get file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Leer los datos del archivo en memoria
	fileData, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Unable to read file", http.StatusInternalServerError)
		return
	}

	// Obtener el ID del usuario desde el formulario
	userIDStr := r.FormValue("userID")
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Llamar a AddFile y manejar posibles errores
	if err := AddFile(userID, fileHeader.Filename, fileData, strconv.FormatInt(fileHeader.Size, 10)); err != nil {
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Archivo cargado exitosamente"))
}

func SignFileHandler(w http.ResponseWriter, r *http.Request) {

	// Parsear el formulario con un límite de 10MB para los archivos
	err := r.ParseMultipartForm(10 << 20) // 10MB
	if err != nil {
		http.Error(w, "Unable to parse form", http.StatusBadRequest)
		return
	}

	// Obtener el archivo del formulario
	file, fileHeader, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Unable to get file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	fmt.Print(fileHeader.Filename)

	// Leer los datos del archivo en memoria
	fileData, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Unable to read file", http.StatusInternalServerError)
		return
	}

	fileIDStr := r.FormValue("fileID")
	fileID, err := strconv.Atoi(fileIDStr)
	if err != nil {
		http.Error(w, "Unable to parse fileID", http.StatusBadRequest)
		return
	}

	var fileToSign models.File
	result := config.DB.Where("id = ?", fileID).First(&fileToSign)
	if result.Error != nil {
		http.Error(w, "Archivo no encontrado", http.StatusNotFound)
		return
	}

	privateKey := string(fileData)
	// Convertir la llave privada desde el string
	privKey, err := utils.ParsePrivateKey(privateKey)
	if err != nil {
		http.Error(w, "Error al convertir la llave privada", http.StatusBadRequest)
		return
	}

	// Firmar el archivo
	signature, err := SignData(privKey, fileToSign.FileData)
	if err != nil {
		http.Error(w, "Error al firmar el archivo", http.StatusInternalServerError)
		return
	}

	userIDStr := r.FormValue("userID")
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		http.Error(w, "Unable to parse userID", http.StatusInternalServerError)
		return
	}

	var existingSignature models.Signatures
	result = config.DB.Where("file_id = ? AND user_id = ?", fileID, userID).First(&existingSignature)
	if result.Error == nil {
		http.Error(w, "El archivo ya está firmado por este usuario", http.StatusConflict)
		return
	}

	// Almacenar la firma en la base de datos
	signatureRecord := models.Signatures{
		FileID:        fileID,
		UserID:        userID,
		FileSignature: signature,
	}

	result = config.DB.Create(&signatureRecord)
	if result.Error != nil {
		http.Error(w, "Error al guardar la firma", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Archivo firmado exitosamente"))
}

func VerifyFileSignatureHandler(w http.ResponseWriter, r *http.Request) {
	// Obtener el ID del archivo desde los parámetros de la solicitud
	vars := mux.Vars(r)
	fileIDStr := vars["fileID"]

	fileID, err := strconv.Atoi(fileIDStr)
	if err != nil {
		http.Error(w, "Invalid file ID", http.StatusBadRequest)
		return
	}

	var signature models.Signatures
	result := config.DB.Where("file_id = ?", fileID).First(&signature)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			// No hay firma encontrada
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]bool{"signed": false})
		} else {
			http.Error(w, "Error querying signatures", http.StatusInternalServerError)
		}
		return
	}

	// Si llegamos aquí, hay una firma encontrada
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]bool{"signed": true})
}

// GenerateKeyPairHandler maneja la generación de llaves RSA, almacenamiento de la llave pública y descarga de la llave privada
func GenerateKeyPairHandler(w http.ResponseWriter, r *http.Request) {

	var userReq models.UserReq

	// Decodificar el JSON del cuerpo de la solicitud
	if err := json.NewDecoder(r.Body).Decode(&userReq); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Generar el par de llaves RSA
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		http.Error(w, "Error al generar la llave", http.StatusInternalServerError)
		return
	}

	// Convertir la llave pública a formato PEM
	pubKeyBytes := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
	pubKeyPem := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}
	pubKeyPemBytes := pem.EncodeToMemory(pubKeyPem)

	// Crear el registro de la llave pública en la base de datos
	publicKey := models.PublicKey{
		UserID:    userReq.UserID,
		PublicKey: string(pubKeyPemBytes),
		KeyName:   userReq.KeyName,
	}

	result := config.DB.Create(&publicKey)
	if result.Error != nil {
		http.Error(w, "Error al almacenar la llave pública", http.StatusInternalServerError)
		return
	}

	// Convertir la llave privada a formato PEM
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privKeyPem := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyBytes,
	}
	privKeyPemBytes := pem.EncodeToMemory(privKeyPem)

	// Configurar la respuesta para la descarga del archivo
	w.Header().Set("Content-Disposition", "attachment; filename="+userReq.KeyName+".pem")
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(privKeyPemBytes)))
	w.WriteHeader(http.StatusOK)

	// Escribir los bytes de la llave privada en la respuesta
	if _, err := w.Write(privKeyPemBytes); err != nil {
		http.Error(w, "Error al escribir el archivo de la llave privada", http.StatusInternalServerError)
		return
	}
}

func VerifySignature(w http.ResponseWriter, r *http.Request) {

	var userReq models.VerifyUserReq

	// Decodificar el JSON del cuerpo de la solicitud
	if err := json.NewDecoder(r.Body).Decode(&userReq); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	var file models.File
	result := config.DB.First(&file, userReq.FileID)
	if result.Error != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	var signature models.Signatures
	result = config.DB.Where("file_id = ?", userReq.FileID).First(&signature)
	if result.Error != nil {
		http.Error(w, "Signature not found", http.StatusNotFound)
		return
	}

	var publicKey models.PublicKey
	result = config.DB.Where("user_id = ?", userReq.UserID).First(&publicKey)
	if result.Error != nil {
		http.Error(w, "Public key not found for user", http.StatusNotFound)
		return
	}

	// Decodificar la clave pública desde el formato PEM en texto
	block, _ := pem.Decode([]byte(publicKey.PublicKey))
	if block == nil || block.Type != "PUBLIC KEY" {
		http.Error(w, "Failed to decode PEM block containing the public key", http.StatusInternalServerError)
		return
	}

	pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		http.Error(w, "Failed to parse public key", http.StatusInternalServerError)
		return
	}

	// Convertir la firma hexadecimal a bytes
	signatureBytes, err := hex.DecodeString(signature.FileSignature)
	if err != nil {
		http.Error(w, "Invalid signature format", http.StatusInternalServerError)
		return
	}

	hash, err := hex.DecodeString(file.FileHash)
	if err != nil {
		http.Error(w, "Invalid hash", http.StatusInternalServerError)
		return
	}

	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash, signatureBytes)
	if err != nil {
		http.Error(w, "Invalid signature", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Signature is valid"))

}

/**SUBIDA Y CONSULTA DE ARCHIVOS**/

func AddFile(userID int, fileName string, fileData []byte, fileSize string) error {
	hashAlg := "SHA256"

	// Crear un nuevo hasher SHA-256
	hasher := sha256.New()

	// Escribir los bytes del archivo en el hasher
	if _, err := hasher.Write(fileData); err != nil {
		return err
	}

	// Obtener el valor final del hash en bytes
	hashInBytes := hasher.Sum(nil)

	// Convertir el hash a una cadena hexadecimal
	hashString := hex.EncodeToString(hashInBytes)

	file := models.File{
		UserID:   userID,
		FileName: fileName,
		FileData: fileData,
		FileHash: hashString,
		HashAlg:  hashAlg,
		FileSize: fileSize,
	}

	// Guardar el archivo en la base de datos
	if err := config.DB.Create(&file).Error; err != nil {
		return err
	}

	return nil
}

func GetFilesByUserID(w http.ResponseWriter, r *http.Request) {

	params := mux.Vars(r)
	userIDStr := params["id"]

	userId, err := strconv.Atoi(userIDStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	var files []models.File
	if err := config.DB.Where("user_id = ?", userId).Find(&files).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(files); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

/** Funciones auxiliares para la firma y verificación de documentos **/

// signData firma los datos con una llave privada RSA
func SignData(privKey *rsa.PrivateKey, data []byte) (string, error) {

	hash := sha256.Sum256(data)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(signature), nil

}
func CheckFileOwner(w http.ResponseWriter, r *http.Request) {
	// Obtener el token del encabezado Authorization
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Invalid authorization header", http.StatusUnauthorized)
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	// Extraer el UserID del JWT
	userID, err := utils.ExtractUserIDFromJWT(tokenString)
	if err != nil {
		http.Error(w, "Could not extract user ID from token", http.StatusUnauthorized)
		return
	}

	// Obtener el ID del archivo del parámetro de la ruta
	params := mux.Vars(r)
	fileIDStr := params["id"]
	fileID, err := strconv.Atoi(fileIDStr)
	if err != nil {
		http.Error(w, "Invalid file ID", http.StatusBadRequest)
		return
	}

	// Consultar el archivo por ID
	var file models.File
	result := config.DB.Where("id = ?", fileID).First(&file)
	if result.Error != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	// Verificar si el archivo pertenece al usuario
	isOwner := file.UserID == userID

	// Enviar la respuesta
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"isOwner": isOwner})
}

func GetSharedFilesHandler(w http.ResponseWriter, r *http.Request) {
	// Obtener el token del encabezado Authorization
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Invalid authorization header", http.StatusUnauthorized)
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	// Extraer el UserID del JWT
	currentUserID, err := utils.ExtractUserIDFromJWT(tokenString)
	if err != nil {
		http.Error(w, "Could not extract user ID from token", http.StatusUnauthorized)
		return
	}

	// Obtener el ID del usuario al que se le está intentando ver los archivos compartidos
	params := mux.Vars(r)
	selectedUserIDStr := params["id"]
	selectedUserID, err := strconv.Atoi(selectedUserIDStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Consultar archivos compartidos por el usuario actual con el usuario seleccionado
	var sharedFiles []models.SharedFile
	result := config.DB.Table("shared").Where("id_user = ? AND id_user_shared = ?", selectedUserID, currentUserID).Find(&sharedFiles)
	if result.Error != nil {
		http.Error(w, "Error retrieving shared files", http.StatusInternalServerError)
		return
	}

	// Depuración: Verificar si hay archivos compartidos
	if len(sharedFiles) == 0 {
		fmt.Println("No shared files found for user:", currentUserID)
		http.Error(w, "No shared files found", http.StatusNotFound)
		return
	}

	// Obtener los IDs de archivos
	var fileIDs []int
	for _, sharedFile := range sharedFiles {
		fileIDs = append(fileIDs, sharedFile.IDFile)
	}

	// Depuración: Verificar los fileIDs que se van a usar en la consulta
	fmt.Println("File IDs to retrieve:", fileIDs)

	// Consultar los archivos con los IDs obtenidos
	var files []models.File
	result = config.DB.Where("id IN (?)", fileIDs).Find(&files)
	if result.Error != nil {
		http.Error(w, "Error retrieving files", http.StatusInternalServerError)
		return
	}

	// Depuración: Verificar si se encontraron archivos
	if len(files) == 0 {
		fmt.Println("No files found for IDs:", fileIDs)
		http.Error(w, "No files found", http.StatusNotFound)
		return
	}

	// Enviar la respuesta
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(files)
}
func GetSharedFilesUsers(w http.ResponseWriter, r *http.Request) {
	// Obtener el token del encabezado Authorization
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Invalid authorization header", http.StatusUnauthorized)
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	// Extraer el UserID del JWT
	userID, err := utils.ExtractUserIDFromJWT(tokenString)
	if err != nil {
		http.Error(w, "Could not extract user ID from token", http.StatusUnauthorized)
		return
	}

	// Consultar usuarios que han compartido archivos con el usuario que inició sesión
	var sharedFiles []models.SharedFile
	result := config.DB.Table("shared").Where("id_user_shared = ?", userID).Find(&sharedFiles)
	if result.Error != nil {
		http.Error(w, "Error retrieving shared files", http.StatusInternalServerError)
		return
	}

	var userIDs []int
	for _, sharedFile := range sharedFiles {
		if !contains(userIDs, sharedFile.IDUser) {
			userIDs = append(userIDs, sharedFile.IDUser)
		}
	}

	var users []models.User
	result = config.DB.Where("id IN (?)", userIDs).Find(&users)
	if result.Error != nil {
		http.Error(w, "Error retrieving users", http.StatusInternalServerError)
		return
	}

	// Enviar la respuesta con la lista de usuarios
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

// Helper function to check if a slice contains an integer
func contains(slice []int, item int) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}
func ShareFileHandler(w http.ResponseWriter, r *http.Request) {
	// Obtener el token del encabezado Authorization
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Invalid authorization header", http.StatusUnauthorized)
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	// Imprimir el token para debug
	fmt.Println("Received Token:", tokenString)

	// Extraer el UserID del JWT
	currentUserID, err := utils.ExtractUserIDFromJWT(tokenString)
	if err != nil {
		http.Error(w, "Could not extract user ID from token", http.StatusUnauthorized)
		return
	}

	// Imprimir el UserID para debug
	fmt.Println("Extracted UserID:", currentUserID)

	// Obtener el fileID de la URL
	fileIDStr := mux.Vars(r)["fileID"]
	fileID, err := strconv.Atoi(fileIDStr)
	if err != nil {
		http.Error(w, "Invalid file ID", http.StatusBadRequest)
		return
	}

	// Decodificar el JSON del cuerpo de la solicitud para obtener el email
	var shareReq ShareRequest
	if err := json.NewDecoder(r.Body).Decode(&shareReq); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Imprimir el payload para debug
	fmt.Printf("Request Payload: Email=%s, FileID=%d, UserID=%d\n", shareReq.Email, shareReq.FileID, shareReq.UserID)

	// Verificar que el archivo pertenezca al usuario actual
	var file models.File
	if result := config.DB.Where("id = ? AND user_id = ?", fileID, currentUserID).First(&file); result.Error != nil {
		http.Error(w, "File not found or you do not have permission to share this file", http.StatusNotFound)
		return
	}

	// Obtener el UserID del usuario con el que se va a compartir el archivo a partir del correo
	var targetUser models.User
	if result := config.DB.Where("email = ?", shareReq.Email).First(&targetUser); result.Error != nil {
		http.Error(w, "User not found with the specified email", http.StatusNotFound)
		return
	}

	// Imprimir el UserID del usuario objetivo para debug
	fmt.Printf("Target UserID: %d\n", targetUser.UserID)

	// Usar el ID del usuario objetivo en lugar del UserID proporcionado en el request
	shareReq.UserID = targetUser.UserID

	// Verificar si ya existe un registro que comparte el archivo con el mismo usuario
	var existingShare models.SharedFile
	if result := config.DB.Table("shared").Where("id_user = ? AND id_user_shared = ? AND id_file = ?", currentUserID, shareReq.UserID, fileID).First(&existingShare); result.Error == nil {
		http.Error(w, "This file is already shared with the specified user", http.StatusConflict)
		return
	}

	// Crear el registro de compartición en la base de datos
	sharedFile := models.SharedFile{
		IDUser:       currentUserID,
		IDUserShared: shareReq.UserID,
		IDFile:       fileID,
	}

	if result := config.DB.Table("shared").Create(&sharedFile); result.Error != nil {
		http.Error(w, "Error sharing file", http.StatusInternalServerError)
		return
	}

	// Enviar una respuesta de éxito
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "File shared successfully"})
}

// verifySignature verifica una firma usando una llave pública RSA
/**
func verifySignature(pubKey *rsa.PublicKey, data []byte, signatureHex string) (bool, error) {
    hash := sha256.Sum256(data)

    signature, err := hex.DecodeString(signatureHex)
    if err != nil {
        return false, err
    }

    err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], signature)
    if err != nil {
        return false, err
    }

    return true, nil
}**/
