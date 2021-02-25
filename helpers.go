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
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/twinj/uuid"
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

func createAuth(username string, td *tokenDetails) error {
	at := time.Unix(td.AtExpires, 0)
	rt := time.Unix(td.RtExpires, 0)
	now := time.Now()

	err := redisClient.Set(td.AccessUUID, username, at.Sub(now)).Err()
	if err != nil {
		return err
	}

	err = redisClient.Set(td.RefreshUUID, username, rt.Sub(now)).Err()
	if err != nil {
		return err
	}
	return nil
}

func deleteAuth(givenUUID string) (int64, error) {
	deleted, err := redisClient.Del(givenUUID).Result()
	if err != nil {
		return 0, err
	}
	return deleted, nil
}

func createJWTToken(username string) (*tokenDetails, error) {
	td := &tokenDetails{}
	td.AtExpires = time.Now().Add(time.Minute * 15).Unix()
	td.AccessUUID = uuid.NewV4().String()

	td.RtExpires = time.Now().Add(time.Hour * 24 * 7).Unix()
	td.RefreshUUID = uuid.NewV4().String()

	atClaims := jwt.MapClaims{}
	atClaims["username"] = username
	atClaims["access_uuid"] = td.AccessUUID
	atClaims["exp"] = td.AtExpires

	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)

	var err error
	td.AccessToken, err = at.SignedString([]byte(cfg.JWT.SecretKey))
	if err != nil {
		return nil, err
	}

	rtClaims := jwt.MapClaims{}
	rtClaims["refresh_uuid"] = td.RefreshUUID
	rtClaims["username"] = username
	rtClaims["exp"] = td.RtExpires
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	td.RefreshToken, err = rt.SignedString([]byte(cfg.JWT.RefreshSecretKey))
	if err != nil {
		return nil, err
	}

	return td, nil
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

func extractTokenMetadata(r *http.Request) (*accessDetails, error) {
	token, err := verifyJWTToken(extractTokenFromRequest(r))
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		accessUUID, ok := claims["access_uuid"].(string)
		if !ok {
			return nil, err
		}
		username, ok := claims["username"].(string)
		if !ok {
			return nil, err
		}
		return &accessDetails{
			AccessUUID: accessUUID,
			Username:   username,
		}, nil
	}

	return nil, nil
}

func verifyJWTToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(cfg.JWT.SecretKey), nil
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
