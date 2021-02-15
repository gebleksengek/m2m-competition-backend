package main

import (
	"encoding/json"
	"net/url"
)

//HTTPResponse http response structure
type HTTPResponse struct {
	Status          bool            `json:"status"`
	Data            json.RawMessage `json:"data"`
	ValidationError url.Values      `json:"validationError,omitempty"`
	ErrorMsg        string          `json:"errorMsg,omitempty"`
}
