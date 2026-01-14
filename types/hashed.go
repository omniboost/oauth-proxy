package types

import (
	"crypto/sha256"
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"
)

type HashedString struct {
	hash string
}

// NewHashedString creates a new HashedString from the provided value(s).
// If multiple strings are provided, they are concatenated with a '|' separator
// before hashing. An empty input results in an empty HashedString.
func NewHashedString(value ...string) HashedString {
	if len(value) == 0 {
		return HashedString{hash: ""}
	}
	fullString := ""
	for _, v := range value {
		fullString += v + "|"
	}
	fullString = strings.TrimSuffix(fullString, "|")
	if fullString == "" {
		return HashedString{hash: ""}
	}

	hashed := sha256.Sum256([]byte(fullString))
	return HashedString{hash: fmt.Sprintf("%x", hashed[:])}
}

func (oes HashedString) String() string {
	return oes.hash
}

func (oes *HashedString) Scan(value interface{}) error {
	switch v := value.(type) {
	case string:
		*oes = HashedString{hash: v}
		return nil
	case []byte:
		*oes = HashedString{hash: string(v)}
		return nil
	}
	return errors.New("optionally encrypted string not supported")
}

func (oes HashedString) Value() (driver.Value, error) {
	return oes.hash, nil
}
