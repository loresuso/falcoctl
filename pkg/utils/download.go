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

// SaveToFile save the body of a http.Response to filepath.
func SaveToFile(content *http.Response, filepath string) error {

	defer content.Body.Close()
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, content.Body)
	return err
}
