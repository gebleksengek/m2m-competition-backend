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
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/kamva/mgm/v3"
	"github.com/nickalie/go-webpbin"
	"github.com/thedevsaddam/govalidator"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"

	ffprobe "github.com/vansante/go-ffprobe"
)

func createAdmin(rw http.ResponseWriter, r *http.Request) {
	result := &HTTPResponse{
		Status: false,
	}

	admin := &Admin{}

	rules := govalidator.MapData{
		"name":            []string{"required", "min:3"},
		"username":        []string{"required", "alpha_num", "between:3,16"},
		"password":        []string{"required", "between:8,32"},
		"profileImageUrl": []string{"url"},
	}

	opts := govalidator.Options{
		Request: r,
		Data:    admin,
		Rules:   rules,
	}

	v := govalidator.New(opts)

	if e := v.ValidateJSON(); len(e) != 0 {
		result.ValidationError = e

		json.NewEncoder(rw).Encode(result)
		return
	}

	hash, err := hashPassword(admin.Password)
	if err != nil {
		result.ErrorMsg = err.Error()

		json.NewEncoder(rw).Encode(result)
		return
	}
	admin.Password = hash

	err = mgm.Coll(admin).FindOne(
		mgm.Ctx(),
		bson.M{
			"username": admin.Username,
		},
	).Err()
	if err == nil {
		log.Println(err)
		result.ErrorMsg = "Username already exist"
		rw.WriteHeader(http.StatusConflict)
		json.NewEncoder(rw).Encode(result)

		return
	}

	err = mgm.Coll(admin).Create(admin)
	if err != nil {
		log.Println(err)
		result.ErrorMsg = err.Error()
		json.NewEncoder(rw).Encode(result)

		return
	}

	adminMarshal, err := json.Marshal(admin)
	if err != nil {
		result.ErrorMsg = err.Error()

		json.NewEncoder(rw).Encode(result)
		return
	}

	result.Data = adminMarshal
	result.Status = true

	json.NewEncoder(rw).Encode(result)
	return
}

func adminLogin(rw http.ResponseWriter, r *http.Request) {
	result := &HTTPResponse{
		Status: false,
	}

	admin := &Admin{}
	adminFromDB := &Admin{}

	rules := govalidator.MapData{
		"username": []string{"required", "alpha_num", "between:3,16"},
		"password": []string{"required", "between:8,32"},
	}

	opts := govalidator.Options{
		Request: r,
		Data:    admin,
		Rules:   rules,
	}

	v := govalidator.New(opts)

	if e := v.ValidateJSON(); len(e) != 0 {
		result.ValidationError = e

		json.NewEncoder(rw).Encode(result)
		return
	}

	err := mgm.Coll(admin).FindOne(
		mgm.Ctx(),
		bson.M{
			"username": admin.Username,
		},
	).Decode(&adminFromDB)
	if err != nil {
		result.ErrorMsg = "Username not exist"
		rw.WriteHeader(http.StatusConflict)
		json.NewEncoder(rw).Encode(result)

		return
	}

	if !adminFromDB.IsActive {
		result.ErrorMsg = "Username not active"
		json.NewEncoder(rw).Encode(result)

		return
	}

	if !checkPasswordHash(admin.Password, adminFromDB.Password) {
		result.ErrorMsg = "Invalid Password"
		json.NewEncoder(rw).Encode(result)

		return
	}

	token, err := createJWTToken(adminFromDB.Username)
	if err != nil {
		result.ErrorMsg = err.Error()
		json.NewEncoder(rw).Encode(result)
		return
	}

	err = createAuth(adminFromDB.Username, token)
	if err != nil {
		result.ErrorMsg = err.Error()
		json.NewEncoder(rw).Encode(result)
		return
	}

	data, err := json.Marshal(
		map[string]interface{}{
			"data": map[string]interface{}{
				"id":                adminFromDB.ID,
				"username":          adminFromDB.Username,
				"name":              adminFromDB.Name,
				"profile_image_url": adminFromDB.ProfileImageURL,
			},
			"accessToken":  token.AccessToken,
			"refreshToken": token.RefreshToken,
		},
	)
	if err != nil {
		result.ErrorMsg = err.Error()
		json.NewEncoder(rw).Encode(result)
		return
	}

	result.Data = data

	result.Status = true

	json.NewEncoder(rw).Encode(result)
	return
}

func adminRefreshToken(rw http.ResponseWriter, r *http.Request) {
	result := &HTTPResponse{}

	mapToken := &struct {
		RefreshToken string `json:"refreshToken"`
	}{}
	rules := govalidator.MapData{
		"refreshToken": []string{"required"},
	}

	opts := govalidator.Options{
		Request: r,
		Data:    mapToken,
		Rules:   rules,
	}

	v := govalidator.New(opts)

	if e := v.ValidateJSON(); len(e) != 0 {
		result.ValidationError = e

		json.NewEncoder(rw).Encode(result)
		return
	}

	refreshToken := mapToken.RefreshToken
	token, err := jwt.Parse(refreshToken, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(cfg.JWT.RefreshSecretKey), nil
	})
	if err != nil {
		log.Println(err)
		result.ErrorMsg = "Refresh token expired"
		json.NewEncoder(rw).Encode(result)
		return
	}
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		log.Println(err)
		result.ErrorMsg = err.Error()
		json.NewEncoder(rw).Encode(result)
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		refreshUUID, ok := claims["refresh_uuid"].(string)
		if !ok {
			log.Println(err)
			result.ErrorMsg = err.Error()
			json.NewEncoder(rw).Encode(result)
			return
		}
		username, ok := claims["username"].(string)
		if !ok {
			log.Println(err)
			result.ErrorMsg = err.Error()
			json.NewEncoder(rw).Encode(result)
			return
		}
		deleted, err := deleteAuth(refreshUUID)
		if err != nil || deleted == 0 {
			log.Println(err)
			result.ErrorMsg = "unauthorized"
			json.NewEncoder(rw).Encode(result)
			return
		}

		ts, err := createJWTToken(username)
		if err != nil {
			log.Println(err)
			result.ErrorMsg = err.Error()
			json.NewEncoder(rw).Encode(result)
			return
		}
		err = createAuth(username, ts)
		if err != nil {
			log.Println(err)
			result.ErrorMsg = err.Error()
			json.NewEncoder(rw).Encode(result)
			return
		}

		result.Data, err = json.Marshal(map[string]string{
			"accessToken":  ts.AccessToken,
			"refreshToken": ts.RefreshToken,
		})

		if err != nil {
			log.Println(err)
			result.ErrorMsg = err.Error()
			json.NewEncoder(rw).Encode(result)
			return
		}
		result.Status = true
	}

	json.NewEncoder(rw).Encode(result)

	return
}

func adminLogout(rw http.ResponseWriter, r *http.Request) {
	result := &HTTPResponse{
		Status: false,
	}
	au, err := extractTokenMetadata(r)
	if err != nil {
		log.Println(err)
		result.ErrorMsg = err.Error()
		json.NewEncoder(rw).Encode(result)
		return
	}
	deleted, err := deleteAuth(au.AccessUUID)
	if err != nil || deleted == 0 {
		log.Println(err)
		result.ErrorMsg = "unauthorized"
		json.NewEncoder(rw).Encode(result)
		return
	}

	result.Status = true
	json.NewEncoder(rw).Encode(result)
	return
}

func adminChangePassword(rw http.ResponseWriter, r *http.Request) {
	result := &HTTPResponse{}

	mapPassword := &struct {
		Password       string `json:"password"`
		PasswordVerify string `json:"verify"`
	}{}

	rules := govalidator.MapData{
		"password": []string{"required", "between:8,32"},
		"verify":   []string{"required", "between:8,32"},
	}

	opts := govalidator.Options{
		Request: r,
		Data:    mapPassword,
		Rules:   rules,
	}

	v := govalidator.New(opts)
	if e := v.ValidateJSON(); len(e) != 0 {
		result.ValidationError = e

		json.NewEncoder(rw).Encode(result)
		return
	}

	if mapPassword.Password != mapPassword.PasswordVerify {
		result.ErrorMsg = "Password and Verify Password not equal"

		json.NewEncoder(rw).Encode(result)
		return
	}

	meta, err := extractTokenMetadata(r)
	if err != nil {
		result.ErrorMsg = err.Error()

		json.NewEncoder(rw).Encode(result)
		return
	}

	admin := &Admin{}

	err = mgm.Coll(admin).FindOne(
		mgm.Ctx(),
		bson.M{
			"username": meta.Username,
		},
	).Decode(&admin)

	if err != nil {
		// result.ErrorMsg = "Username not exist"
		result.ErrorMsg = err.Error()

		json.NewEncoder(rw).Encode(result)
		return
	}

	hash, err := hashPassword(mapPassword.Password)
	if err != nil {
		result.ErrorMsg = err.Error()

		json.NewEncoder(rw).Encode(result)
		return
	}
	admin.Password = hash
	admin.UpdatedAt = time.Now()

	err = mgm.Coll(admin).Update(
		admin,
	)
	if err != nil {
		result.ErrorMsg = err.Error()

		json.NewEncoder(rw).Encode(result)
		return
	}

	result.Status = true

	json.NewEncoder(rw).Encode(result)
	return
}

func createCarousel(rw http.ResponseWriter, r *http.Request) {
	result := &HTTPResponse{
		Status: false,
	}

	rules := govalidator.MapData{
		"title":        []string{"required", "min:3"},
		"description":  []string{},
		"file:content": []string{"required", "ext:mp4", "mime:video/mp4"},
	}

	opts := govalidator.Options{
		Request: r,
		Rules:   rules,
	}

	v := govalidator.New(opts)

	if e := v.Validate(); len(e) != 0 {
		result.ValidationError = e
		json.NewEncoder(rw).Encode(result)

		return
	}

	r.ParseMultipartForm(0)

	carousel := &Carousel{
		Uploader: &Uploader{},
		Content: &Content{
			Title:       r.FormValue("title"),
			Description: r.FormValue("description"),
		},
	}

	tokenString := extractTokenFromRequest(r)
	token, _ := verifyJWTToken(tokenString)
	claims := token.Claims.(jwt.MapClaims)
	username := claims["username"].(string)

	adminData := &Admin{}

	err := mgm.Coll(adminData).FindOne(
		mgm.Ctx(),
		bson.M{
			"username": username,
		},
	).Decode(&adminData)
	if err != nil {
		result.ErrorMsg = err.Error()

		rw.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(rw).Encode(result)

		return
	}

	if !adminData.IsActive {
		result.ErrorMsg = "Username not active"

		rw.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(rw).Encode(result)

		return
	}

	carousel.Uploader.Name = adminData.Name
	carousel.Uploader.Username = adminData.Username
	carousel.Uploader.ProfileImageURL = adminData.ProfileImageURL

	content, contentHeader, err := r.FormFile("content")
	if err != nil {
		log.Println(err)
		result.ErrorMsg = err.Error()
		json.NewEncoder(rw).Encode(result)
		return
	}

	fileName := fmt.Sprintf(
		"%s_-_%s_-_%s",
		carousel.Content.Title,
		carousel.Uploader.Username,
		contentHeader.Filename,
	)
	file, err := gDriveClient.CreateFile(fileName, "video/mp4", content, gDriveClient.Config.CarouselDirectoryID)
	if err != nil {
		log.Println(err)
		result.ErrorMsg = err.Error()
		json.NewEncoder(rw).Encode(result)
		return
	}
	_, err = gDriveClient.ShareReadToAnyone(file.Id)
	if err != nil {
		log.Println(err)
		result.ErrorMsg = err.Error()
		json.NewEncoder(rw).Encode(result)
		return
	}

	carousel.Content.ID = file.Id
	carousel.Content.URL = fmt.Sprintf("https://drive.google.com/uc?export=view&id=%s", file.Id)

	contentData, err := ffprobe.GetProbeData(carousel.Content.URL, 1*time.Minute)
	if err != nil {
		log.Println(err)
		result.ErrorMsg = err.Error()
		json.NewEncoder(rw).Encode(result)
		return
	}

	carousel.Content.Duration = contentData.Format.Duration().Milliseconds()

	err = mgm.Coll(carousel).Create(carousel)
	if err != nil {
		log.Println(err)
		result.ErrorMsg = err.Error()
		json.NewEncoder(rw).Encode(result)
		return
	}

	carouselMarshal, err := json.Marshal(carousel)
	if err != nil {
		log.Println(err)
		result.ErrorMsg = err.Error()
		json.NewEncoder(rw).Encode(result)
		return
	}

	result.Data = carouselMarshal
	result.Status = true

	json.NewEncoder(rw).Encode(result)
	return
}

func getAllCarousel(rw http.ResponseWriter, r *http.Request) {
	result := &HTTPResponse{}

	sortQ, _ := r.URL.Query()["sort"]
	sort := "1"

	if len(sortQ) > 0 {
		sort = sortQ[0]
	}

	if sort != "1" &&
		sort != "-1" {
		sort = "1"
	}
	sortN, _ := strconv.Atoi(sort)

	carousels := []Carousel{}

	findOptions := &options.FindOptions{}
	findOptions.SetSort(bson.M{"updated_at": sortN})

	err := mgm.Coll(&Carousel{}).SimpleFind(&carousels, bson.M{}, findOptions)
	if err != nil {
		log.Println(err)
		result.ErrorMsg = err.Error()
		json.NewEncoder(rw).Encode(result)
		return
	}

	carouselsMarshal, err := json.Marshal(carousels)
	if err != nil {
		log.Println(err)
		result.ErrorMsg = err.Error()
		json.NewEncoder(rw).Encode(result)
		return
	}

	result.Data = carouselsMarshal

	result.Status = true

	json.NewEncoder(rw).Encode(result)
	return
}

func createGallery(rw http.ResponseWriter, r *http.Request) {
	result := &HTTPResponse{}

	rules := govalidator.MapData{
		"title":        []string{"required", "min:3"},
		"description":  []string{},
		"file:content": []string{"required", "ext:jpg,jpeg,png", "mime:image/jpg,image/jpeg,image/png"},
	}

	opts := govalidator.Options{
		Request: r,
		Rules:   rules,
	}

	v := govalidator.New(opts)

	if e := v.Validate(); len(e) != 0 {
		result.ValidationError = e
		json.NewEncoder(rw).Encode(result)

		return
	}

	r.ParseMultipartForm(0)

	gallery := &Gallery{
		Uploader: &Uploader{},
		Content: &ContentGallery{
			Title:       r.FormValue("title"),
			Description: r.FormValue("description"),
		},
	}

	tokenString := extractTokenFromRequest(r)
	token, _ := verifyJWTToken(tokenString)
	claims := token.Claims.(jwt.MapClaims)
	username := claims["username"].(string)

	adminData := &Admin{}

	err := mgm.Coll(adminData).FindOne(
		mgm.Ctx(),
		bson.M{
			"username": username,
		},
	).Decode(&adminData)
	if err != nil {
		result.ErrorMsg = err.Error()

		rw.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(rw).Encode(result)

		return
	}

	if !adminData.IsActive {
		result.ErrorMsg = "Username not active"

		rw.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(rw).Encode(result)

		return
	}

	gallery.Uploader.Name = adminData.Name
	gallery.Uploader.Username = adminData.Username
	gallery.Uploader.ProfileImageURL = adminData.ProfileImageURL

	content, contentHeader, err := r.FormFile("content")
	if err != nil {
		log.Println(err)
		result.ErrorMsg = err.Error()
		json.NewEncoder(rw).Encode(result)
		return
	}
	fileHeader := make([]byte, 512)
	if _, err := content.Read(fileHeader); err != nil {
		log.Println(err)
		result.ErrorMsg = err.Error()
		json.NewEncoder(rw).Encode(result)
		return
	}
	if _, err := content.Seek(0, 0); err != nil {
		log.Println(err)
		result.ErrorMsg = err.Error()
		json.NewEncoder(rw).Encode(result)
		return
	}

	contentMimeType := http.DetectContentType(fileHeader)

	fileName := fmt.Sprintf(
		"%s_-_%s_-_%s",
		gallery.Content.Title,
		gallery.Uploader.Username,
		contentHeader.Filename,
	)
	file, err := gDriveClient.CreateFile(fileName, contentMimeType, content, gDriveClient.Config.GalleryDirectoryID)
	if err != nil {
		log.Println(err)
		result.ErrorMsg = err.Error()
		json.NewEncoder(rw).Encode(result)
		return
	}
	_, err = gDriveClient.ShareReadToAnyone(file.Id)
	if err != nil {
		log.Println(err)
		result.ErrorMsg = err.Error()
		json.NewEncoder(rw).Encode(result)
		return
	}
	gallery.Content.ID = file.Id
	gallery.Content.URL = fmt.Sprintf("https://drive.google.com/uc?export=view&id=%s", file.Id)

	err = mgm.Coll(gallery).Create(gallery)
	if err != nil {
		log.Println(err)
		result.ErrorMsg = err.Error()
		json.NewEncoder(rw).Encode(result)
		return
	}

	galleryMarshal, err := json.Marshal(gallery)
	if err != nil {
		log.Println(err)
		result.ErrorMsg = err.Error()
		json.NewEncoder(rw).Encode(result)
		return
	}

	result.Data = galleryMarshal
	result.Status = true

	json.NewEncoder(rw).Encode(result)
	return
}

func getAllContestant(rw http.ResponseWriter, r *http.Request) {
	result := &HTTPResponse{}

	sortQ, _ := r.URL.Query()["sort"]
	sortByQ, _ := r.URL.Query()["sort_by"]
	limitQ, _ := r.URL.Query()["limit"]
	pageQ, _ := r.URL.Query()["page"]

	sortBy := "updated_at"
	sort := "1"
	limit := 1
	page := 1

	if len(sortQ) > 0 {
		sort = sortQ[0]
		if sort != "1" &&
			sort != "-1" {
			sort = "1"
		}
	}
	if len(sortByQ) > 0 {
		sortBy = sortByQ[0]
	}
	if len(limitQ) > 0 {
		if i, e := strconv.Atoi(limitQ[0]); e == nil {
			if i >= 0 {
				limit = i
			}
		}
	}
	if len(pageQ) > 0 {
		if i, e := strconv.Atoi(pageQ[0]); e == nil {
			if i >= 1 {
				page = i
			}
		}
	}

	sortN, _ := strconv.Atoi(sort)

	contestant := []Contestant{}

	skip := page*limit - limit

	findOptions := &options.FindOptions{}
	if page != 0 {
		findOptions.SetLimit(int64(limit))
		findOptions.SetSort(bson.M{sortBy: sortN})
		findOptions.SetSkip(int64(skip))
	}

	err := mgm.Coll(&Contestant{}).SimpleFind(&contestant, bson.M{}, findOptions)
	if err != nil {
		log.Println(err)
		result.ErrorMsg = err.Error()
		json.NewEncoder(rw).Encode(result)
		return
	}
	total, err := mgm.Coll(&Contestant{}).CountDocuments(mgm.Ctx(), bson.M{})
	if err != nil {
		log.Println(err)
		result.ErrorMsg = err.Error()
		json.NewEncoder(rw).Encode(result)
		return
	}

	resultMarshal, err := json.Marshal(map[string]interface{}{
		"data":    contestant,
		"sort_by": sortBy,
		"sort":    sort,
		"limit":   limit,
		"page":    page,
		"total":   total,
	})
	if err != nil {
		log.Println(err)
		result.ErrorMsg = err.Error()
		json.NewEncoder(rw).Encode(result)
		return
	}

	result.Data = resultMarshal
	result.Status = true

	json.NewEncoder(rw).Encode(result)
	return
}

func getGalleries(rw http.ResponseWriter, r *http.Request) {
	result := &HTTPResponse{}

	sortQ, _ := r.URL.Query()["sort"]
	limitQ, _ := r.URL.Query()["limit"]
	pageQ, _ := r.URL.Query()["page"]

	sort := "1"
	limit := 10
	page := 1

	if len(sortQ) > 0 {
		sort = sortQ[0]
		if sort != "1" &&
			sort != "-1" {
			sort = "1"
		}
	}
	if len(limitQ) > 0 {
		if i, e := strconv.Atoi(limitQ[0]); e == nil {
			if i >= 1 {
				limit = i
			}
		}
	}
	if len(pageQ) > 0 {
		if i, e := strconv.Atoi(pageQ[0]); e == nil {
			if i >= 1 {
				page = i
			}
		}
	}

	sortN, _ := strconv.Atoi(sort)

	galleries := []Gallery{}

	skip := page*limit - limit

	findOptions := &options.FindOptions{}
	findOptions.SetLimit(int64(limit))
	findOptions.SetSort(bson.M{"updated_at": sortN})
	findOptions.SetSkip(int64(skip))

	err := mgm.Coll(&Gallery{}).SimpleFind(&galleries, bson.M{}, findOptions)
	if err != nil {
		log.Println(err)
		result.ErrorMsg = err.Error()
		json.NewEncoder(rw).Encode(result)
		return
	}

	admins := map[string]Admin{}

	for i, v := range galleries {
		if val, ok := admins[v.Uploader.Username]; ok {
			galleries[i].Uploader.Name = val.Name
			galleries[i].Uploader.ProfileImageURL = val.ProfileImageURL
			galleries[i].Uploader.Username = val.Username
			continue
		}

		admin := &Admin{}
		err := mgm.Coll(admin).FindOne(
			mgm.Ctx(),
			bson.M{
				"username": v.Uploader.Username,
			},
		).Decode(&admin)
		if err != nil {
			log.Println(err)
			continue
		}
		admins[admin.Username] = *admin
		galleries[i].Uploader.Name = admin.Name
		galleries[i].Uploader.ProfileImageURL = admin.ProfileImageURL
		galleries[i].Uploader.Username = admin.Username
	}

	galleriesMarshal, err := json.Marshal(galleries)
	if err != nil {
		log.Println(err)
		result.ErrorMsg = err.Error()
		json.NewEncoder(rw).Encode(result)
		return
	}

	result.Data = galleriesMarshal

	result.Status = true

	json.NewEncoder(rw).Encode(result)
	return
}

func uploadVideo(rw http.ResponseWriter, r *http.Request) {
	result := &HTTPResponse{
		Status: false,
	}

	rules := govalidator.MapData{
		"name":       []string{"required", "min:3"},
		"email":      []string{"required", "email"},
		"school":     []string{"required", "min:8"},
		"title":      []string{"required"},
		"phone":      []string{"required", "phone"},
		"file:video": []string{"required", "ext:mp4", "mime:video/mp4"},
	}

	opts := govalidator.Options{
		Request: r,
		Rules:   rules,
	}

	v := govalidator.New(opts)

	if e := v.Validate(); len(e) != 0 {
		result.ValidationError = e
		json.NewEncoder(rw).Encode(result)

		return
	}

	r.ParseMultipartForm(0)

	contestant := &Contestant{
		Name:   r.FormValue("name"),
		Email:  r.FormValue("email"),
		School: r.FormValue("school"),
		Title:  r.FormValue("title"),
		Phone:  r.FormValue("phone"),
		Video:  &ContestantVideo{},
	}

	err := mgm.Coll(contestant).Create(contestant)
	if err != nil {
		log.Println(err)
		result.ErrorMsg = err.Error()
		json.NewEncoder(rw).Encode(result)
		return
	}

	video, videoHeader, err := r.FormFile("video")
	if err != nil {
		log.Println(err)
		result.ErrorMsg = err.Error()
		json.NewEncoder(rw).Encode(result)
		return
	}

	videoName := fmt.Sprintf(
		"%s_-_%s_-_%s_-_%s",
		contestant.Title,
		contestant.Name,
		contestant.School,
		videoHeader.Filename,
	)
	file, err := gDriveClient.CreateFile(videoName, "video/mp4", video, gDriveClient.Config.ContestantDirectoryID)
	if err != nil {
		log.Println(err)
	}
	_, err = gDriveClient.ShareReadToAnyone(file.Id)
	if err != nil {
		log.Println(err)
	}

	contestant.Video.ID = file.Id
	contestant.Video.URL = fmt.Sprintf("https://drive.google.com/uc?export=view&id=%s", file.Id)

	err = mgm.Coll(contestant).Update(contestant)
	if err != nil {
		log.Println(err)
		result.ErrorMsg = err.Error()
		json.NewEncoder(rw).Encode(result)
		return
	}

	contestantMarshal, err := json.Marshal(contestant)
	if err != nil {
		result.ErrorMsg = err.Error()
		json.NewEncoder(rw).Encode(result)
		return
	}

	result.Data = contestantMarshal

	result.Status = true

	json.NewEncoder(rw).Encode(result)
	return
}

func getVideo(rw http.ResponseWriter, r *http.Request) {
	result := &HTTPResponse{
		Status: false,
	}

	vars := mux.Vars(r)
	id := vars["id"]

	_, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		result.ErrorMsg = "Data Not Found"

		rw.WriteHeader(http.StatusNotFound)
		json.NewEncoder(rw).Encode(result)
		return
	}

	contestant := &Contestant{}

	err = mgm.Coll(contestant).FindByID(id, contestant)
	if err != nil {
		result.ErrorMsg = "Data Not Found"

		rw.WriteHeader(http.StatusNotFound)
		json.NewEncoder(rw).Encode(result)
		return
	}

	contestantMarshal, err := json.Marshal(contestant)
	if err != nil {
		log.Println(err)
		result.ErrorMsg = err.Error()
		json.NewEncoder(rw).Encode(result)
		return
	}

	result.Data = contestantMarshal

	result.Status = true

	json.NewEncoder(rw).Encode(result)
	return
}

func getAsset(rw http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	asset, err := gDriveClient.DownloadFile(id)
	if err != nil {
		log.Println(err)
		return
	}

	rw.Header().Set("Cache-Control", "public, max-age=31536000")

	webpbin.SkipDownload()
	err = webpbin.NewCWebP().Quality(80).Input(asset.Body).Output(rw).Run()
	if err != nil {
		log.Panicln(err)
		return
	}

	asset.Body.Close()
	return
}

//Router create parent router
func Router() *mux.Router {
	router := mux.NewRouter().StrictSlash(true)

	apiV1 := router.PathPrefix("/api/v1").Subrouter()
	admin := apiV1.PathPrefix("/admin").Subrouter()
	contest := apiV1.PathPrefix("/contest").Subrouter()
	carousel := apiV1.PathPrefix("/carousel").Subrouter()
	gallery := apiV1.PathPrefix("/gallery").Subrouter()
	assets := apiV1.PathPrefix("/assets").Subrouter()

	apiV1.Use(CORSMiddleware)

	admin.Use(JSONResponseMiddleware)
	admin.HandleFunc("/create", createAdmin).Methods("POST", "OPTIONS")
	admin.HandleFunc("/login", adminLogin).Methods("POST", "OPTIONS")
	admin.HandleFunc("/logout", adminLogout).Methods("GET", "OPTIONS")
	admin.HandleFunc("/refresh-token", adminRefreshToken).Methods("POST", "OPTIONS")

	adminAuth := admin.PathPrefix("/").Subrouter()
	adminAuth.Use(VerifyAuthTokenMiddleware)

	adminAuthProfile := adminAuth.PathPrefix("/profile").Subrouter()
	adminAuthProfile.HandleFunc("/change-password", adminChangePassword).Methods("PUT", "OPTIONS")

	adminAuthManage := adminAuth.PathPrefix("/manage").Subrouter()
	adminAuthManage.HandleFunc("/carousel", createCarousel).Methods("POST", "OPTIONS")
	adminAuthManage.HandleFunc("/gallery", createGallery).Methods("POST", "OPTIONS")

	adminAuthContestant := adminAuth.PathPrefix("/contestant").Subrouter()
	adminAuthContestant.HandleFunc("/list", getAllContestant).Methods("GET", "OPTIONS")

	contest.Use(JSONResponseMiddleware)
	contest.HandleFunc("/uploadVideo", uploadVideo).Methods("POST", "OPTIONS")
	contest.HandleFunc("/video/{id}", getVideo).Methods("GET", "OPTIONS")

	carousel.Use(JSONResponseMiddleware)
	carousel.HandleFunc("", getAllCarousel).Methods("GET", "OPTIONS")

	gallery.Use(JSONResponseMiddleware)
	gallery.HandleFunc("", getGalleries).Methods("GET", "OPTIONS")

	assets.HandleFunc("/{id}", getAsset).Methods("GET", "OPTIONS")

	return router
}
