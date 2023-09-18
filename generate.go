//go:build ignore
// +build ignore

package main

import (
	"log"
	"net/http"
)

//go:generate xo schema sqlite://db/production.sqlite3?loc=auto -o db
//go:generate go run generate.go

func main() {
	var fs http.FileSystem = http.Dir("assets")
	err := vfsgen.Generate(fs, vfsgen.Options{
		PackageName:  "oauthproxy",
		VariableName: "Assets",
	})
	if err != nil {
		log.Fatalln(err)
	}
}
