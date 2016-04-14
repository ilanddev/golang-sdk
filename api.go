/*
Package iland provides a basic API wrapper for accessing the iland cloud API.

The package handles API token retrieval and renewal behind the scenes.

There are methods for performing the following types of HTTP requests:

	GET
	POST
	PUT
	DELETE

*/
package iland

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is an iland cloud SDK client.
type Client struct {
	Config          *Config
	Token           *Token
	TokenExpireTime time.Time
}

// NewClient cretes a new iland API Client to interact with the iland cloud API.
func NewClient(cfg *Config) *Client {
	client := &Client{cfg, nil, time.Now()}
	return client
}

// Config object to hold properties related to API access. You pass this to the NewClient method to create a new iland cloud API client.
type Config struct {
	APIBaseURL   string
	AccessURL    string
	RefreshURL   string
	ClientID     string
	ClientSecret string
	Username     string
	Password     string
}

// Token object for holding access token and expiration time of iland cloud API token.
type Token struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
}

// TokenRequest object for holding params required for requesting a new iland cloud API token.
type TokenRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	GrantType    string `json:"grant_type"`
}

// RefreshTokenRequest object for holding params required for requesting a new iland cloud API token.
type RefreshTokenRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RefreshToken string `json:"refresh_token"`
	GrantType    string `json:"grant_type"`
}

// APIError holds messages and details around errors from the iland cloud API.
type APIError struct {
	Error         string `json:"error"`
	Message       string `json:"message"`
	DetailMessage string `json:"detail_message"`
}

// Get an API access token from the iland cloud API.
func (c *Client) getToken() {
	tokenRequest := TokenRequest{c.Config.ClientID, c.Config.ClientSecret, c.Config.Username, c.Config.Password, "password"}
	form := url.Values{}
	form.Add("client_id", tokenRequest.ClientID)
	form.Add("client_secret", tokenRequest.ClientSecret)
	form.Add("username", tokenRequest.Username)
	form.Add("password", tokenRequest.Password)
	form.Add("grant_type", tokenRequest.GrantType)
	resp, err := http.Post(c.Config.AccessURL, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	var t Token
	err = json.Unmarshal(body, &t)
	if err != nil {
		log.Fatal(err)
	}
	c.Token = &t
	c.setTokenExpireTime()
}

// Get an API access token from the iland cloud API.
func (c *Client) refreshToken() {
	tokenRequest := RefreshTokenRequest{c.Config.ClientID, c.Config.ClientSecret, c.Token.AccessToken, "refresh_token"}
	form := url.Values{}
	form.Add("client_id", tokenRequest.ClientID)
	form.Add("client_secret", tokenRequest.ClientSecret)
	form.Add("refresh_token", tokenRequest.RefreshToken)
	form.Add("grant_type", tokenRequest.GrantType)
	resp, err := http.Post(c.Config.RefreshURL, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	var t Token
	err = json.Unmarshal(body, &t)
	if err != nil {
		log.Fatal(err)
	}
	c.Token = &t
	c.setTokenExpireTime()
}

// Set the token expiration time so we can auto-renew it when necessary.
func (c *Client) setTokenExpireTime() {
	var buffer int64 = 10
	c.TokenExpireTime = time.Now().Add(time.Duration(c.Token.ExpiresIn-buffer) * time.Second)
	log.Println("Auth token expires at:", c.TokenExpireTime)
}

// Remove the JSON hijacking prefix the iland cloud API adds.
func removeJSONHijackingPrefix(b []byte) string {
	return strings.TrimPrefix(string(b), ")]}'")
}

// Perform an HTTP request with the given relative path and HTTP
// method type, any payload can be provided as a string.
func (c *Client) doRequest(relPath, verb, payload string) (string, error) {
	c.refreshTokenIfNecessary()
	client := &http.Client{}
	path := c.Config.APIBaseURL + relPath
	log.Println("Fetching: " + path)
	bytesJSON := bytes.NewBuffer([]byte(payload))
	req, err := http.NewRequest(verb, path, bytesJSON)
	req.Header.Add("Authorization", "Bearer "+c.Token.AccessToken)
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	// check for response other than 200, 201, 202, and 204 as they denote API error
	statusCode := resp.StatusCode
	responseBody := removeJSONHijackingPrefix(body)
	if statusCode != 200 && statusCode != 201 && statusCode != 202 && statusCode != 204 {
		// co-erce the return into an ilandcloud API error and get the detail message if possible
		var e APIError
		err = json.Unmarshal([]byte(responseBody), &e)
		if err != nil {
			return "", fmt.Errorf("Error marshaling ApiError: %s", err.Error())
		}
		var errMsg string
		if e.DetailMessage != "" {
			errMsg = e.DetailMessage
		} else {
			errMsg = e.Message
		}
		return responseBody, errors.New(errMsg)
	}
	// Remove JSON Hijacking prefix
	return responseBody, nil
}

// Refresh the iland cloud API token if necessary.
func (c *Client) refreshTokenIfNecessary() {
	if !c.isValidToken() {
		log.Println("Retriving a new iland cloud API token.")
		c.getToken()
	} else {
		//refresh the existing token
		log.Println("Refreshing iland cloud API token.")
		c.refreshToken()
	}
}

// Check whether the current iland cloud API token is valid.
func (c *Client) isValidToken() bool {
	if time.Now().After(c.TokenExpireTime) {
		return false
	}
	return true
}

// Get performs a GET request to the iland cloud API to the given relative path.
func (c *Client) Get(relPath string) (string, error) {
	return c.doRequest(relPath, "GET", "")
}

// Post performs a POST request to the iland cloud API to the given relative path
// and using the given JSON payload.
func (c *Client) Post(relPath, jsonStr string) (string, error) {
	return c.doRequest(relPath, "POST", jsonStr)
}

// Put performs a PUT request to the iland cloud API to the given relative path
// and using the given JSON payload.
func (c *Client) Put(relPath, jsonStr string) (string, error) {
	return c.doRequest(relPath, "PUT", jsonStr)
}

// Delete performs a DELETE request to the iland cloud API to the given relative path.
func (c *Client) Delete(relPath string) (string, error) {
	return c.doRequest(relPath, "DELETE", "")
}
