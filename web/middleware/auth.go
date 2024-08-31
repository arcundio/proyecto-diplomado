package middleware

import (
	"context"
	"net/http"
	"strings"
	"web/utils"
)

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header is required", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		email, err := utils.VerifyToken(tokenString)
		if err != nil {
			http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
			return
		}

		// Si es necesario, puedes almacenar el email en el contexto y pasarlo a los handlers siguientes
		ctx := r.Context()
		ctx = context.WithValue(ctx, "email", email)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}
