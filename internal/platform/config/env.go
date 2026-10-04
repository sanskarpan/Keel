package config

import "os"

func lookupEnvironment(key string) string {
	return os.Getenv(key)
}
