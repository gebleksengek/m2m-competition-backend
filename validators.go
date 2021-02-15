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
