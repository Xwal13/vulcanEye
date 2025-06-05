package main

import (
	"bytes"
	"crypto/tls"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// fetchURL performs GET or POST requests and returns the response body and headers.
func fetchURL(cfg *ScanConfig, u string, method string, data url.Values, extraHeaders map[string]string) (string, http.Header, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: tr}

	var req *http.Request
	var err error
	if method == "POST" {
		req, err = http.NewRequest("POST", u, strings.NewReader(data.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req, err = http.NewRequest("GET", u, nil)
	}

	if err != nil {
		return "", nil, err
	}

	req.Header.Set("User-Agent", "pwntwo/1.0")
	if cfg.Cookie != "" {
		req.Header.Set("Cookie", cfg.Cookie)
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	debugPrintf(cfg, "%s %s", method, u)
	if data != nil && len(data) > 0 {
		debugPrintf(cfg, "POST data: %s", data.Encode())
	}
	if cfg.Cookie != "" {
		debugPrintf(cfg, "Using Cookie: %s", cfg.Cookie)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(resp.Body)
	return string(bodyBytes), resp.Header, nil
}

// fetchMultipart handles multipart file uploads
func fetchMultipart(cfg *ScanConfig, u string, params map[string]string, fileField, fileName string, fileContent []byte, extraHeaders map[string]string) (string, http.Header, error) {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	for key, val := range params {
		w.WriteField(key, val)
	}
	if fileField != "" && fileName != "" && fileContent != nil {
		fw, err := w.CreateFormFile(fileField, fileName)
		if err != nil {
			return "", nil, err
		}
		_, err = fw.Write(fileContent)
		if err != nil {
			return "", nil, err
		}
	}
	w.Close()

	req, err := http.NewRequest("POST", u, &b)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("User-Agent", "pwntwo/1.0")
	req.Header.Set("Content-Type", w.FormDataContentType())
	if cfg.Cookie != "" {
		req.Header.Set("Cookie", cfg.Cookie)
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(resp.Body)
	return string(bodyBytes), resp.Header, nil
}

// extractParamsFromURL splits a URL into its base and query params.
func extractParamsFromURL(rawurl string) (string, url.Values, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return "", nil, err
	}
	params, _ := url.ParseQuery(u.RawQuery)
	u.RawQuery = ""
	return u.String(), params, nil
}