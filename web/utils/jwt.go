package utils

import (
    "github.com/golang-jwt/jwt/v5"
    "time"
    "os"
    "fmt"
)

var ErrSecretKeyNotFound = fmt.Errorf("clave secreta no configurada")

func GenerateToken(email string) (string, error) {


    // Obtener la clave secreta del entorno
    secretKey := os.Getenv("JWT_SECRET_KEY")
    if secretKey == "" {
        return "", ErrSecretKeyNotFound
    }

    // Crear un nuevo token JWT
    token := jwt.New(jwt.SigningMethodHS256)

    // Definir los claims del token
    claims := token.Claims.(jwt.MapClaims)
    claims["email"] = email
    claims["exp"] = time.Now().Add(time.Hour * 1).Unix() // Expira en 1 hora

    // Firmar el token con la clave secreta
    signedToken, err := token.SignedString([]byte(secretKey))
    if err != nil {
        return "", err
    }

    return signedToken, nil
}

// VerifyToken verifica un token JWT y devuelve el correo electrónico si el token es válido
func VerifyToken(tokenString string) (string, error) {
    // Obtener la clave secreta del entorno
    secretKey := os.Getenv("JWT_SECRET_KEY")
    if secretKey == "" {
        return "", ErrSecretKeyNotFound
    }

    // Parsear el token usando la clave secreta
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        // Verificar que el algoritmo es el esperado
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("algoritmo inesperado: %v", token.Header["alg"])
        }
        return []byte(secretKey), nil
    })
    if err != nil {
        return "", err
    }

    // Validar el token
    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok || !token.Valid {
        return "", fmt.Errorf("token inválido")
    }

    // Extraer el correo electrónico del token
    email, ok := claims["email"].(string)
    if !ok {
        return "", fmt.Errorf("correo electrónico no encontrado en el token")
    }

    return email, nil
}

