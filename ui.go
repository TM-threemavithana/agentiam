package agentiam

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed web/dist/*
var webDist embed.FS

// GetUIFS returns the embedded filesystem for the React UI.
func GetUIFS() (http.FileSystem, error) {
	sub, err := fs.Sub(webDist, "web/dist")
	if err != nil {
		return nil, err
	}
	return http.FS(sub), nil
}
