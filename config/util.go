// Copyright (C) 2017, Beijing Bochen Technology Co.,Ltd.  All rights reserved.
//
// This file is part of L0
//
// The L0 is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The L0 is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package config

import (
	"time"

	"github.com/spf13/viper"
)

func getInt(key string, defaultValue int) int {
	var (
		value int
	)
	if value = viper.GetInt(key); value == 0 {
		return defaultValue
	}
	return value
}

func getString(key string, defaultValue string) string {
	var (
		value string
	)
	if value = viper.GetString(key); value == "" {
		return defaultValue
	}
	return value
}

func getStringSlice(key string, defaultValue []string) []string {
	var (
		value []string
	)
	if value = viper.GetStringSlice(key); len(value) == 0 {
		return defaultValue
	}
	return value
}

func getDuration(key string, defaultValue time.Duration) time.Duration {
	var (
		value string
	)
	if value = viper.GetString(key); value == "" {
		return defaultValue
	}
	if duration, err := time.ParseDuration(value); err == nil {
		return duration
	}
	return defaultValue
}

func getbool(key string, defaultValue bool) bool {
	var (
		value bool
	)
	if value = viper.GetBool(key); value == false {
		return defaultValue
	}
	return value
}
