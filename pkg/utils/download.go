package utils

import (
	"io"
	"net/http"
	"os"
)

// DownloadFile download a file from a given URL
func DownloadFile(url string) (*http.Response, error) {

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// SaveToFile writes data to filepath.
func SaveToFile(data []byte, filepath string) error {

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.WriteString(out, string(data))
	return err
}
