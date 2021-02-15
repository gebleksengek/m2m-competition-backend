package main

import (
	"fmt"
	"log"

	"github.com/kamva/mgm/v3"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

//MongoDBConfig mongodb config structure
type MongoDBConfig struct {
	Username string
	Password string
	Host     string
	Port     int
	Database string
}

//Admin user admin model for mongodb
type Admin struct {
	mgm.DefaultModel `bson:",inline"`
	Name             string `json:"name" bson:"name"`
	Username         string `json:"username" bson:"username"`
	ProfileImageURL  string `json:"profileImageUrl" bson:"profileImageUrl"`
	Password         string `json:"password" bson:"password"`
	IsActive         bool   `json:"isActive" bson:"isActive"`
}

//Uploader carousel uploader data
type Uploader struct {
	Name            string `json:"name" bson:"name"`
	Username        string `json:"username" bson:"username"`
	ProfileImageURL string `json:"profileImageUrl" bson:"profileImageUrl"`
}

//Content carousel content data
type Content struct {
	Title       string `json:"title" bson:"title"`
	Description string `json:"description" bson:"description"`
	Duration    int64  `json:"duration" bson:"duration"`
	ID          string `json:"id" bson:"id"`
	URL         string `json:"url" bson:"url"`
}

//Carousel mongodb carousel model
type Carousel struct {
	mgm.DefaultModel `bson:",inline"`
	Uploader         *Uploader `json:"uploader" bson:"uploader"`
	Content          *Content  `json:"content" bson:"content"`
}

//ContentGallery gallery content data
type ContentGallery struct {
	Title       string `json:"title" bson:"title"`
	Description string `json:"description" bson:"description"`
	ID          string `json:"id" bson:"id"`
	URL         string `json:"url" bson:"url"`
}

//Gallery mongodb gallery model
type Gallery struct {
	mgm.DefaultModel `bson:",inline"`
	Uploader         *Uploader       `json:"uploader" bson:"uploader"`
	Content          *ContentGallery `json:"content" bson:"content"`
}

//ContestantVideo constant video info for google drive
type ContestantVideo struct {
	URL string `json:"url" bson:"url"`
	ID  string `json:"id" bson:"id"`
}

//Contestant mongodb contestant model
type Contestant struct {
	mgm.DefaultModel `bson:",inline"`
	Name             string           `json:"name" bson:"name"`
	Email            string           `json:"email" bson:"email"`
	Phone            string           `json:"phone" bson:"phone"`
	School           string           `json:"school" bson:"school"`
	Title            string           `json:"title" bson:"title"`
	Video            *ContestantVideo `json:"video" bson:"video"`
}

//MongoDBInitialize init mongo db connection
func MongoDBInitialize(mongoDBConfig MongoDBConfig) {
	mongoURI := fmt.Sprintf(
		"mongodb://%s:%s@%s:%d/%s",
		mongoDBConfig.Username,
		mongoDBConfig.Password,
		mongoDBConfig.Host,
		mongoDBConfig.Port,
		mongoDBConfig.Database,
	)
	log.Printf("Connecting to MongoDB: %s\n", mongoURI)

	err := mgm.SetDefaultConfig(
		nil,
		mongoDBConfig.Database,
		options.Client().ApplyURI(mongoURI),
	)

	if err != nil {
		log.Fatal(err)
	}

	client, err := mongo.Connect(nil, options.Client().ApplyURI(mongoURI))

	if err != nil {
		log.Fatal(err)
	}

	defer func() {
		if err = client.Disconnect(mgm.Ctx()); err != nil {
			log.Fatal(err)
		}
	}()

	if err := client.Ping(mgm.Ctx(), readpref.Primary()); err != nil {
		log.Fatal(err)
	} else {
		log.Println("Success to connect MongoDB")
	}
}
