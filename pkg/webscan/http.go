package webscan

import (
	"Yasso/config"
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
)

//TODO: dismap RespLab

type RespLab struct {
	Url            string
	RespBody       string
	RespHeader     string
	RespStatusCode string
	RespTitle      string
	FaviconMd5     string
}

func FaviconMd5(Url string, timeout time.Duration, Path string) string {
	client := &http.Client{
		Timeout: time.Duration(timeout),
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	Url = Url + "/favicon.ico"
	req, err := http.NewRequest("GET", Url, nil)
	if err != nil {
		return ""
	}
	for key, value := range config.DefaultHeader {
		req.Header.Set(key, value)
	}
	//req.Header.Set("Accept-Language", "zh,zh-TW;q=0.9,en-US;q=0.8,en;q=0.7,zh-CN;q=0.6")
	//req.Header.Set("User-agent", "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36")
	//req.Header.Set("Cookie", "rememberMe=int")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body_bytes, err := ioutil.ReadAll(resp.Body)
	hash := md5.Sum(body_bytes)
	md5 := fmt.Sprintf("%x", hash)
	return md5
}

func DefaultRequests(Url string, timeout time.Duration) []RespLab {

	var redirect_url string
	var resp_title string
	var response_header string
	var response_body string
	var response_status_code string
	var res []string

	// Set up HTTP request client
	client := &http.Client{
		Timeout: time.Duration(timeout),
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest("GET", Url, nil)
	if err != nil {
		return nil
	}
	// Set default request headers
	for key, value := range config.DefaultHeader {
		req.Header.Set(key, value)
	}
	// Make HTTP request
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Get request status code
	var status_code = resp.StatusCode
	response_status_code = strconv.Itoa(status_code)

	//TODO: Intercept status code based on request, if it's 30x then need to intercept URL for redirection

	if len(regexp.MustCompile("30").FindAllStringIndex(response_status_code, -1)) == 1 {
		// Perform redirection
		redirect_path := resp.Header.Get("Location") // Intercept URL for redirection request
		if len(regexp.MustCompile("http").FindAllStringIndex(redirect_path, -1)) == 1 {
			redirect_url = redirect_path
		} else {
			redirect_url = Url + redirect_path
		}
		client = &http.Client{
			Timeout: time.Duration(timeout),
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		// Set up redirection request
		req, err := http.NewRequest("GET", redirect_url, nil)
		if err != nil {
			return nil
		}
		for key, value := range config.DefaultHeader {
			req.Header.Set(key, value)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil
		}
		defer resp.Body.Close()

		//TODO: Solve the problem of double 30x redirects
		var twoStatusCode = resp.StatusCode
		responseStatusCodeTwo := strconv.Itoa(twoStatusCode)
		if len(regexp.MustCompile("30").FindAllStringIndex(responseStatusCodeTwo, -1)) == 1 {
			redirectPath := resp.Header.Get("Location")
			if len(regexp.MustCompile("http").FindAllStringIndex(redirectPath, -1)) == 1 {
				redirect_url = redirectPath
			} else {
				redirect_url = Url + redirectPath
			}
			client = &http.Client{
				Timeout: time.Duration(timeout),
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
			req, err := http.NewRequest("GET", redirect_url, nil)
			if err != nil {
				return nil
			}
			for key, value := range config.DefaultHeader {
				req.Header.Set(key, value)
			}
			resp, err := client.Do(req)
			if err != nil {
				return nil
			}
			defer resp.Body.Close()
			// get response body for string
			bodyBytes, err := ioutil.ReadAll(resp.Body)
			response_body = string(bodyBytes)
			// Solve the problem of garbled body codes with unmatched numbers
			if !utf8.Valid(bodyBytes) {
				data, _ := simplifiedchinese.GBK.NewDecoder().Bytes(bodyBytes)
				response_body = string(data)
			}
			// Get Response title
			grepTitle := regexp.MustCompile("<title>(.*)</title>")
			if len(grepTitle.FindStringSubmatch(response_body)) != 0 {
				resp_title = grepTitle.FindStringSubmatch(response_body)[1]
			} else {
				resp_title = "None"
			}
			for name, values := range resp.Header {
				for _, value := range values {
					res = append(res, fmt.Sprintf("%s: %s", name, value))
				}
			}
			for _, re := range res {
				response_header += re + "\n"
			}
			favicon5 := FaviconMd5(Url, timeout, "")
			RespData := []RespLab{
				{redirect_url, response_body, response_header, response_status_code, resp_title, favicon5},
			}
			return RespData
		}
		// get response body for string
		body_bytes, err := ioutil.ReadAll(resp.Body)
		response_body = string(body_bytes)
		// Solve the problem of garbled body codes with unmatched numbers
		if !utf8.Valid(body_bytes) {
			data, _ := simplifiedchinese.GBK.NewDecoder().Bytes(body_bytes)
			response_body = string(data)
		}
		// Get Response title
		grep_title := regexp.MustCompile("<title>(.*)</title>")
		if len(grep_title.FindStringSubmatch(response_body)) != 0 {
			resp_title = grep_title.FindStringSubmatch(response_body)[1]
		} else {
			resp_title = "None"
		}
		// get response header for string
		for name, values := range resp.Header {
			for _, value := range values {
				res = append(res, fmt.Sprintf("%s: %s", name, value))
			}
		}
		for _, re := range res {
			response_header += re + "\n"
		}
		favicon5 := FaviconMd5(Url, timeout, "")
		RespData := []RespLab{
			{redirect_url, response_body, response_header, response_status_code, resp_title, favicon5},
		}
		return RespData
	}
	// get response body for string
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	response_body = string(bodyBytes)
	// Solve the problem of garbled body codes with unmatched numbers
	if !utf8.Valid(bodyBytes) {
		data, _ := simplifiedchinese.GBK.NewDecoder().Bytes(bodyBytes)
		response_body = string(data)
	}

	// Get Response title
	grep_title := regexp.MustCompile("<title>(.*)</title>")
	if len(grep_title.FindStringSubmatch(response_body)) != 0 {
		resp_title = grep_title.FindStringSubmatch(response_body)[1]
	} else {
		resp_title = "None"
	}
	// get response header for string
	for name, values := range resp.Header {
		for _, value := range values {
			res = append(res, fmt.Sprintf("%s: %s", name, value))
		}
	}
	for _, re := range res {
		response_header += re + "\n"
	}
	faviconmd5 := FaviconMd5(Url, timeout, "")
	RespData := []RespLab{
		{Url, response_body, response_header, response_status_code, resp_title, faviconmd5},
	}
	return RespData
}

func CustomRequests(Url string, timeout time.Duration, Method string, Path string, Header []string, Body string) []RespLab {
	var respTitle string
	// Splicing Custom Path
	u, err := url.Parse(Url)
	u.Path = path.Join(u.Path, Path)
	Url = u.String()
	if strings.HasSuffix(Path, "/") {
		Url = Url + "/"
	}
	client := &http.Client{
		Timeout: time.Duration(timeout),
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	// Send Http requests
	body_byte := bytes.NewBuffer([]byte(Body))
	req, err := http.NewRequest(Method, Url, body_byte)
	if err != nil {
		return nil
	}

	// Set Requests Headers
	for _, header := range Header {
		grep_key := regexp.MustCompile("(.*): ")
		var header_key = grep_key.FindStringSubmatch(header)[1]
		grep_value := regexp.MustCompile(": (.*)")
		var header_value = grep_value.FindStringSubmatch(header)[1]
		req.Header.Set(header_key, header_value)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	// Get Response Body for string
	body_bytes, err := ioutil.ReadAll(resp.Body)
	var response_body = string(body_bytes)
	// Solve the problem of garbled body codes with unmatched numbers
	if !utf8.Valid(body_bytes) {
		data, _ := simplifiedchinese.GBK.NewDecoder().Bytes(body_bytes)
		response_body = string(data)
	}
	// Get Response title
	grep_title := regexp.MustCompile("<title>(.*)</title>")
	if len(grep_title.FindStringSubmatch(response_body)) != 0 {
		respTitle = grep_title.FindStringSubmatch(response_body)[1]
	} else {
		respTitle = "None"
	}
	// Get Response Header for string
	var res []string
	for name, values := range resp.Header {
		for _, value := range values {
			res = append(res, fmt.Sprintf("%s: %s", name, value))
		}
	}
	var response_header string
	for _, re := range res {
		response_header += re + "\n"
	}
	// get response status code
	var status_code = resp.StatusCode
	response_status_code := strconv.Itoa(status_code)
	RespData := []RespLab{
		{Url, response_body, response_header, response_status_code, respTitle, ""},
	}
	return RespData
}

// Parse IP for dismap

func ParseUrl(host string, port string) string {
	if port == "80" {
		return "http://" + host
	} else if port == "443" {
		return "https://" + host
	} else if len(regexp.MustCompile("443").FindAllStringIndex(port, -1)) == 1 {
		return "https://" + host + ":" + port
	} else {
		return "http://" + host + ":" + port
	}
}
