package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

//ResponseJSONMarshal convert struct to json for response api
func ResponseJSONMarshal(result *HTTPResponse) string {
	marshall, err := json.Marshal(result)
	if err != nil {
		marshall, _ = json.Marshal(&HTTPResponse{Status: false})
		return string(marshall)
	}

	return string(marshall)
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10)

	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))

	return err == nil
}

func createJWTToken(secretKey, username string) (string, error) {
	atClaims := jwt.MapClaims{}
	atClaims["username"] = username
	atClaims["exp"] = time.Now().Add(time.Minute * 15).Unix()

	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)

	token, err := at.SignedString([]byte(secretKey))
	if err != nil {
		return "", err
	}

	return token, nil
}

func extractTokenFromRequest(r *http.Request) string {
	bearToken := r.Header.Get("Authorization")
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		if strArr[0] != "Bearer" {
			return ""
		}
		return strArr[1]
	}
	return ""
}

func verifyJWTToken(secretKey, tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secretKey), nil
	})
	if err != nil {
		return nil, err
	}

	claims, _ := token.Claims.(jwt.MapClaims)
	if claims["username"] == nil ||
		claims["exp"] == nil {
		return nil, fmt.Errorf("invalid jwt token")
	}

	usernameType := reflect.TypeOf(claims["username"]).Kind()
	expType := reflect.TypeOf(claims["exp"]).Kind()
	if usernameType != reflect.String ||
		expType != reflect.Float64 {
		return nil, fmt.Errorf("invalid jwt token")
	}

	return token, nil
}

func isTokenValid(token *jwt.Token) bool {
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		return false
	}

	return true
}
