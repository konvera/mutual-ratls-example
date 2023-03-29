package mutual_ratls

import (
	"os"
	"encoding/hex"
)

func GetSGXEnvVar(key string) []byte {
	if os.Getenv(key) != "" {
		val, err := hex.DecodeString(os.Getenv(key))
		if err == nil {
			return val
		}
	}

	return nil
}