package controllers

import (
    "encoding/json"
    "crypto/x509"
    "net/http"
    "web/config"
    "web/models"
    "web/utils"
    "github.com/gorilla/mux"
    "golang.org/x/crypto/bcrypt"
    "crypto/sha256"
    "encoding/hex"
    "crypto/rsa"
    "crypto/rand"
    "crypto"
    "io"
    "encoding/pem"
)


// Login maneja la autenticación y genera un token JWT
func Login(w http.ResponseWriter, r *http.Request) {
    var credentials struct {
        Email    string `json:"email"`
        Passwrd string `json:"passwrd"`
    }
    if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }

    var user models.User
    result := config.DB.Where("email = ?", credentials.Email).First(&user)
    if result.Error != nil {
        http.Error(w, "User not found", http.StatusUnauthorized)
        return
    }

    // Verificar la contraseña
    err := bcrypt.CompareHashAndPassword([]byte(user.Passwrd), []byte(credentials.Passwrd))
    if err != nil {
        http.Error(w, "Invalid password", http.StatusUnauthorized)
        return
    }

    // Generar el token
    token, err := utils.GenerateToken(user.Email)
    if err != nil {
        http.Error(w, "Could not generate token", http.StatusInternalServerError)
        return
    }

    // Enviar el token en la respuesta
    response := map[string]string{"token": token}
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
    var users []models.User
    config.DB.Find(&users)
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
    // Leer el cuerpo de la solicitud
    body, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, "Error al leer el cuerpo de la solicitud", http.StatusInternalServerError)
        return
    }

    // Deserializar el JSON en una estructura
    var request models.UploadFileRequest
    if err := json.Unmarshal(body, &request); err != nil {
        http.Error(w, "Error al deserializar el JSON", http.StatusBadRequest)
        return
    }

    // Convertir la representación hexadecimal a bytes
    fileData, err := hex.DecodeString(request.FileData)
    if err != nil {
        http.Error(w, "Error al decodificar los datos del archivo", http.StatusBadRequest)
        return
    }

    // Crear el archivo en la base de datos
    AddFile(request.UserID, request.FileName, fileData, request.FileSize)

    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Archivo cargado exitosamente"))
}

func SignFileHandler(w http.ResponseWriter, r *http.Request) {

    // Leer el cuerpo de la solicitud
    var request models.SignFileRequest
    if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
        http.Error(w, "Error al deserializar el JSON", http.StatusBadRequest)
        return
    }

    // Verificar si el archivo es válido y existe
    var file models.File
    result := config.DB.Where("id = ?", request.FileID).First(&file)
    if result.Error != nil {
        http.Error(w, "Archivo no encontrado", http.StatusNotFound)
        return
    }

    // Verificar si la firma ya existe
    var existingSignature models.Signature
    result = config.DB.Where("file_id = ? AND user_id = ?", request.FileID, request.UserID).First(&existingSignature)
    if result.Error == nil {
        http.Error(w, "El archivo ya está firmado por este usuario", http.StatusConflict)
        return
    }

    // Convertir la llave privada desde el string
    privKey, err := utils.ParsePrivateKey(request.PrivateKey)
    if err != nil {
        http.Error(w, "Error al convertir la llave privada", http.StatusBadRequest)
        return
    }

    // Firmar el archivo
    signature, err := SignData(privKey, file.FileData)
    if err != nil {
        http.Error(w, "Error al firmar el archivo", http.StatusInternalServerError)
        return
    }

    // Almacenar la firma en la base de datos
    signatureRecord := models.Signature{
        FileID:    request.FileID,
        UserID:    request.UserID,
        Signature: signature,
    }

    result = config.DB.Create(&signatureRecord)
    if result.Error != nil {
        http.Error(w, "Error al guardar la firma", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Archivo firmado exitosamente"))
}



// GenerateKeyPairHandler maneja la generación de llaves RSA, almacenamiento de la llave pública y descarga de la llave privada
func GenerateKeyPairHandler(w http.ResponseWriter, r *http.Request) {
    var request models.GenerateKeyPairRequest
    if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
        http.Error(w, "Error al deserializar el JSON", http.StatusBadRequest)
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
        UserID: request.UserID,
        PublicKey:    string(pubKeyPemBytes),
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
    w.Header().Set("Content-Disposition", "attachment; filename=private_key.pem")
    w.Header().Set("Content-Type", "application/x-pem-file")
    w.Header().Set("Content-Length", string(len(privKeyPemBytes)))
    w.WriteHeader(http.StatusOK)
    
    // Escribir los bytes de la llave privada en la respuesta
    if _, err := w.Write(privKeyPemBytes); err != nil {
        http.Error(w, "Error al escribir el archivo de la llave privada", http.StatusInternalServerError)
        return
    }
}

/**SUBIDA Y CONSULTA DE ARCHIVOS**/

func AddFile(userID uint, fileName string, fileData []byte, fileSize string) {

    hashAlg := "SHA256"

    // Crear un nuevo hasher SHA-256
    hasher := sha256.New()

    // Escribir los bytes del archivo en el hasher
    hasher.Write(fileData)

    // Obtener el valor final del hash en bytes
    hashInBytes := hasher.Sum(nil)

    // Convertir el hash a una cadena hexadecimal
    hashString := hex.EncodeToString(hashInBytes)

    file := models.File {
        UserID:   userID,
        FileName: fileName,
        FileData: fileData,
        FileHash: hashString,
        HashAlg: hashAlg,
        FileSize: fileSize,
    }

    config.DB.Create(&file)
}

func GetFilesByUserID(userID uint) ([]models.File, error) {
    var files []models.File
    result := config.DB.Where("user_id = ?", userID).Find(&files)
    return files, result.Error
}

// VerifySignatureHandler maneja la verificación de una firma
/**
func VerifySignatureHandler(c *gin.Context) {
    var request models.VerifySignatureRequest
    if err := c.BindJSON(&request); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Error al deserializar el JSON"})
        return
    }

    // Obtener el archivo desde la base de datos
    var file models.File
    result := config.DB.First(&file, request.FileID)
    if result.Error != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "Archivo no encontrado"})
        return
    }

    // Obtener la llave pública desde la base de datos
    var pubKey models.PublicKey
    result = config.DB.Where("user_id = ?", file.UserID).First(&pubKey)
    if result.Error != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "Llave pública no encontrada"})
        return
    }

    pubKeyParsed, err := parsePublicKey(pubKey.Key)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Error al parsear la llave pública"})
        return
    }

    // Verificar la firma
    isValid, err := verifySignature(pubKeyParsed, file.FileData, request.Signature)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Error al verificar la firma"})
        return
    }

    if isValid {
        c.JSON(http.StatusOK, gin.H{"message": "Firma válida"})
    } else {
        c.JSON(http.StatusBadRequest, gin.H{"message": "Firma no válida"})
    }
}**/


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