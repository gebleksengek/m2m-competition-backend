package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/drive/v3"
	"google.golang.org/api/googleapi"
)

//GDriveClient init gdrive
type GDriveClient struct {
	Credential string
	Config     GDriveClientConfig
	Service    *drive.Service
}

//GDriveClientConfig gdrive config
type GDriveClientConfig struct {
	SaveDirectory         string
	SaveDirectoryID       string
	ContestantDirectoryID string
	CarouselDirectoryID   string
	GalleryDirectoryID    string
}

func validateCredPath(path string) error {
	s, err := os.Stat(path)
	if err != nil {
		return err
	}
	if s.IsDir() {
		return fmt.Errorf("'%s' is a directory, not a normal file", path)
	}

	return nil
}

func getTokenFromFile(filePath string) (*oauth2.Token, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tok := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(tok)

	return tok, err
}

func getTokenFromWeb(config *oauth2.Config) *oauth2.Token {
	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("Go to the following link in your browser then type the "+
		"authorization code: \n%v\n", authURL)

	var authCode string
	fmt.Printf("Authorization Code: ")
	if _, err := fmt.Scan(&authCode); err != nil {
		log.Fatalf("Unable to read authorization code %v", err)
	}

	tok, err := config.Exchange(context.TODO(), authCode)
	if err != nil {
		log.Fatalf("Unable to retrieve token from web %v", err)
	}

	return tok
}

func saveToken(filePath string, token *oauth2.Token) {
	fmt.Printf("Saving credential file to: %s\n", filePath)

	f, err := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Unable to cache oauth token: %v", err)
	}
	defer f.Close()
	json.NewEncoder(f).Encode(token)
}

func getClient(config *oauth2.Config) *http.Client {
	tokenFile := "token.json"
	tok, err := getTokenFromFile(tokenFile)
	if err != nil {
		tok = getTokenFromWeb(config)
		saveToken(tokenFile, tok)
	}

	return config.Client(context.Background(), tok)
}

//Setup Google Drive First Setup
func (gDriveClient GDriveClient) Setup() (*GDriveClient, error) {
	if gDriveClient.Config.SaveDirectory == "" {
		gDriveClient.Config.SaveDirectory = "M2M Gdrive Backend"
	}

	b, err := ioutil.ReadFile(gDriveClient.Credential)
	if err != nil {
		return nil, err
	}

	config, err := google.ConfigFromJSON(b, drive.DriveScope)
	if err != nil {
		log.Fatalf("Unable to parse client secret file to config: %v", err)
	}
	client := getClient(config)

	service, err := drive.New(client)
	if err != nil {
		log.Fatalf("Unable to retrieve Drive client: %v", err)
	}

	gDriveClient.Service = service

	log.Printf("Creating directory '%s' if not exist.\n", gDriveClient.Config.SaveDirectory)
	saveDir, _ := gDriveClient.CreateDirIfNotExist(gDriveClient.Config.SaveDirectory, "root")
	gDriveClient.Config.SaveDirectoryID = saveDir.Id
	log.Printf("Google Drive Save Directory ID: %s\n", gDriveClient.Config.SaveDirectoryID)

	log.Printf("Creating directory 'contestant' if not exist.\n")
	contestantDir, _ := gDriveClient.CreateDirIfNotExist("contestant", gDriveClient.Config.SaveDirectoryID)
	gDriveClient.Config.ContestantDirectoryID = contestantDir.Id
	log.Printf("Google Drive Save Directory ID: %s\n", gDriveClient.Config.ContestantDirectoryID)

	log.Printf("Creating directory 'carousel' if not exist.\n")
	carouselDir, _ := gDriveClient.CreateDirIfNotExist("carousel", gDriveClient.Config.SaveDirectoryID)
	gDriveClient.Config.CarouselDirectoryID = carouselDir.Id
	log.Printf("Google Drive Save Directory ID: %s\n", gDriveClient.Config.CarouselDirectoryID)

	log.Printf("Creating directory 'gallery' if not exist.\n")
	galleryDir, _ := gDriveClient.CreateDirIfNotExist("gallery", gDriveClient.Config.SaveDirectoryID)
	gDriveClient.Config.GalleryDirectoryID = galleryDir.Id
	log.Printf("Google Drive Save Directory ID: %s\n", gDriveClient.Config.GalleryDirectoryID)

	return &gDriveClient, nil
}

//CreateDirIfNotExist create dir if not exists
func (gDriveClient GDriveClient) CreateDirIfNotExist(name string, parentID string) (*drive.File, error) {
	var searchQuery []string
	searchQuery = append(searchQuery, fmt.Sprintf("name = '%s'", name))
	searchQuery = append(searchQuery, "and mimeType = 'application/vnd.google-apps.folder'")
	searchQuery = append(searchQuery, "and trashed=false")

	listCall := gDriveClient.Service.Files.List().Fields("nextPageToken, files(id)").Q(strings.Join(searchQuery, " "))
	var pageToken string
	var file *drive.File

	for {
		r, err := listCall.PageToken(pageToken).Do()
		if err != nil {
			log.Fatalf("An error occurred: %v", err)
		}

		if len(r.Files) > 0 {
			file = r.Files[0]
		} else {
			d, err := gDriveClient.CreateDir(name, parentID)
			if err != nil {
				log.Fatalf("Could not create dir '%s': %v", name, err)
				return nil, err
			}
			file = d
		}

		if pageToken = r.NextPageToken; pageToken == "" {
			break
		}
	}

	return file, nil
}

//CreateDir create directory in google drive
func (gDriveClient GDriveClient) CreateDir(name string, parentID string) (*drive.File, error) {
	d := &drive.File{
		Name:     name,
		MimeType: "application/vnd.google-apps.folder",
		Parents:  []string{parentID},
	}

	file, err := gDriveClient.Service.Files.Create(d).Do()
	if err != nil {
		return nil, err
	}
	return file, nil
}

//CreateFile create file in google drive
func (gDriveClient GDriveClient) CreateFile(name string, mimeType string, content io.Reader, parentID string) (*drive.File, error) {
	f := &drive.File{
		Name:     name,
		MimeType: mimeType,
		Parents:  []string{parentID},
	}

	file, err := gDriveClient.Service.Files.Create(f).Media(content).Do()
	if err != nil {
		return nil, err
	}

	return file, nil
}

//GetFile get file by id
func (gDriveClient GDriveClient) GetFile(fileID string, fields ...googleapi.Field) (*drive.File, error) {
	file, err := gDriveClient.Service.Files.Get(fileID).Fields(fields...).Do()
	if err != nil {
		return nil, err
	}

	return file, nil
}

//DownloadFile download file from google drive
func (gDriveClient GDriveClient) DownloadFile(fileID string) (*http.Response, error) {
	res, err := gDriveClient.Service.Files.Get(fileID).Download()
	if err != nil {
		return nil, err
	}

	return res, nil
}

//ShareReadToAnyone share file to anyone with read permission
func (gDriveClient GDriveClient) ShareReadToAnyone(fileID string) (*drive.Permission, error) {
	permission, err := gDriveClient.Service.Permissions.Create(fileID, &drive.Permission{
		Type: "anyone",
		Role: "reader",
	}).Do()

	if err != nil {
		return nil, err
	}

	return permission, nil
}

//ListAllFile list all file in gdrive
func (gDriveClient GDriveClient) ListAllFile() {
	r, err := gDriveClient.Service.Files.List().PageSize(10).Fields("nextPageToken, files(id, name, mimeType, videoMediaMetadata)").Do()
	if err != nil {
		log.Fatalf("Unable to retrieve files: %v", err)
	}

	fmt.Println("Files")
	if len(r.Files) == 0 {
		fmt.Println("No files found.")
	} else {
		for _, i := range r.Files {
			fmt.Printf("%s (%v) - %s\n", i.Name, i.VideoMediaMetadata, i.MimeType)
		}
	}
}
