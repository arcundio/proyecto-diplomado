package utils

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"os"
	"time"
)

var ErrSecretKeyNotFound = fmt.Errorf("clave secreta no configurada")

type Claims struct {
	Email  string `json:"email"`
	UserID int    `json:"userID"`
	jwt.RegisteredClaims
}

// Modificar GenerateToken para incluir UserID
func GenerateToken(email string, userID int) (string, error) {
	secretKey := os.Getenv("JWT_SECRET_KEY")
	if secretKey == "" {
		return "", fmt.Errorf("JWT_SECRET_KEY not found")
	}

	claims := Claims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 1)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
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

func ExtractUserIDFromJWT(tokenString string) (int, error) {
	secretKey := os.Getenv("JWT_SECRET_KEY")
	if secretKey == "" {
		return 0, fmt.Errorf("JWT_SECRET_KEY not found")
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})
	if err != nil {
		return 0, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return 0, fmt.Errorf("invalid token")
	}

	return claims.UserID, nil
}
