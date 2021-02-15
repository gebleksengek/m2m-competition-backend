package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
)

var gDriveClient *GDriveClient
var jwtConfig struct {
	SecretKey string
}

// RunServer will run the HTTP Server
func (config Config) RunServer() {
	runChan := make(chan os.Signal, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 30)
	defer cancel()

	server := &http.Server{
		Addr:    config.Server.Host + ":" + config.Server.Port,
		Handler: Router(),
	}

	signal.Notify(runChan, os.Interrupt)

	log.Printf("Server is starting on %s\n", server.Addr)

	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("Server failed to start due to err: %v", err)
		}
	}()

	interrupt := <-runChan

	log.Printf("Server is shutting down due to %+v\n", interrupt)
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server was unable to gracefully shutdown due to err: %+v", err)
	}
}

func main() {
	cfgPath, err := ParseFlags()
	if err != nil {
		log.Fatal(err)
	}
	cfg, err := NewConfig(cfgPath)
	if err != nil {
		log.Fatal(err)
	}

	mongoDBConfig := MongoDBConfig{
		Username: cfg.MongoDB.Username,
		Password: cfg.MongoDB.Password,
		Host:     cfg.MongoDB.Host,
		Port:     cfg.MongoDB.Port,
		Database: cfg.MongoDB.Database,
	}

	MongoDBInitialize(mongoDBConfig)

	initClient, err := GDriveClient{
		Credential: cfg.Google.Drive.Credential,
		Config: GDriveClientConfig{
			SaveDirectory: cfg.Google.Drive.SaveDirectory,
		},
	}.Setup()
	if err != nil {
		log.Fatal(err)
	}
	gDriveClient = initClient
	jwtConfig.SecretKey = cfg.JWT.SecretKey

	initGovalidatorCustomRule()

	cfg.RunServer()
}
