package main

import (
	"encoding/json"
	"net/http"
)

//CORSMiddleware middleware for handling cors
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Access-Control-Allow-Origin", "*")
		next.ServeHTTP(rw, r)
	})
}

//JSONResponseMiddleware middleware for set json header response
func JSONResponseMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(rw, r)
	})
}

//VerifyAuthTokenMiddleware middleware for verify token authorization
func VerifyAuthTokenMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		tokenString := extractTokenFromRequest(r)
		token, err := verifyJWTToken(jwtConfig.SecretKey, tokenString)
		if err != nil {
			result := &HTTPResponse{}
			result.ErrorMsg = err.Error()

			rw.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(rw).Encode(result)
			return
		}
		if valid := isTokenValid(token); !valid {
			result := &HTTPResponse{}
			result.ErrorMsg = "invalid jwt token"

			rw.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(rw).Encode(result)
			return
		}

		next.ServeHTTP(rw, r)
	})
}
