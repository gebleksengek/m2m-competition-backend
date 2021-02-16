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
	"fmt"
	"regexp"

	"github.com/thedevsaddam/govalidator"
	"github.com/ttacon/libphonenumber"
)

func initGovalidatorCustomRule() {
	govalidator.AddCustomRule("phone", func(field, rule, message string, value interface{}) error {
		val := value.(string)

		simpleRegex := `^(0|62|\+62)[0-9]*$`
		isValid, err := regexp.MatchString(simpleRegex, val)
		if err != nil {
			return fmt.Errorf("The %s field error: %s", field, err.Error())
		}
		if isValid == false {
			return fmt.Errorf("The %s field must be an Indonesian Telephone Number", field)
		}

		num, err := libphonenumber.Parse(val, "ID")
		if err != nil {
			return fmt.Errorf("The %s field error: %s", field, err.Error())
		}
		isValid = libphonenumber.IsValidNumberForRegion(num, "ID")
		if isValid == false {
			return fmt.Errorf("The %s field must be an Indonesian Telephone Number", field)
		}
		isValid = libphonenumber.IsPossibleNumber(num)
		if isValid == false {
			return fmt.Errorf("The %s field must be an Indonesian Telephone Number", field)
		}
		err = libphonenumber.ParseToNumber(val, "ID", num)
		if err != nil {
			return fmt.Errorf("The %s field error: %s", field, err.Error())
		}

		return nil
		// fmt.Println(num)
		// return fmt.Errorf("The %s field must be an Indonesian Telephone Number", field)

	})

}
