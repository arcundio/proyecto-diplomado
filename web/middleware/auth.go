package middleware

import (

    "net/http"
    "github.com/golang-jwt/jwt/v5"
    "os"
)

// Middleware para verificar el token JWT
func AuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Obtener el token del encabezado Authorization
        tokenString := r.Header.Get("Authorization")
        if tokenString == "" {
            http.Error(w, "Falta el token de autenticación", http.StatusUnauthorized)
            return
        }

        // Eliminar el prefijo "Bearer " del token
        tokenString = tokenString[len("Bearer "):]

        // Obtener la clave secreta del entorno
        secretKey := os.Getenv("JWT_SECRET_KEY")
        if secretKey == "" {
            http.Error(w, "Clave secreta no configurada", http.StatusInternalServerError)
            return
        }

        // Verificar el token
        token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
            // Verificar el algoritmo utilizado
            if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                return nil, jwt.ErrSignatureInvalid
            }
            return []byte(secretKey), nil
        })

        if err != nil || !token.Valid {
            http.Error(w, "Token inválido", http.StatusUnauthorized)
            return
        }

        // Continuar con la solicitud si el token es válido
        next.ServeHTTP(w, r)
    })
}
