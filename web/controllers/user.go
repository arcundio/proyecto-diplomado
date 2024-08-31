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
    "strconv"
    "fmt"
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


    userIDStr := r.FormValue("userID")
    userID, err := strconv.Atoi(userIDStr)
    if err != nil {
        http.Error(w, "Invalid user code", http.StatusBadRequest)
        return
    }

    fileSizeInt := fileHeader.Size
    fileSizeStr := strconv.FormatInt(fileSizeInt, 10)


    AddFile(userID, fileHeader.Filename, fileData, fileSizeStr)
    

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
    signatureRecord := models.Signatures {
        FileID:    fileID,
        UserID:    userID,
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
        UserID:       userReq.UserID,
        PublicKey:    string(pubKeyPemBytes),
        KeyName:      userReq.KeyName,
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

func AddFile(userID int, fileName string, fileData []byte, fileSize string) {

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