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
	"net/url"
)

//HTTPResponse http response structure
type HTTPResponse struct {
	Status          bool            `json:"status"`
	Data            json.RawMessage `json:"data"`
	ValidationError url.Values      `json:"validationError,omitempty"`
	ErrorMsg        string          `json:"errorMsg,omitempty"`
}
