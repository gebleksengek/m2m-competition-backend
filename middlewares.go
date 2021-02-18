// Copyright (C) 2021 Administrator
//
// This file is part of backend.
//
// backend is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// backend is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with backend.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"encoding/json"
	"net/http"
)

//CORSMiddleware middleware for handling cors
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Access-Control-Allow-Origin", "*")
		rw.Header().Set("Access-Control-Allow-Headers", "Content-Type")
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
