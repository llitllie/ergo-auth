package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"github.com/go-jose/go-jose/v3"
)

var (
	ErrUserNoFound = errors.New("user no found")
	ErrAuthFailed  = errors.New("auth failed")
)

type AuthScriptInput struct {
	AccountName string `json:"accountName,omitempty"`
	Passphrase  string `json:"passphrase,omitempty"`
	Certfp      string `json:"certfp,omitempty"`
	IP          string `json:"ip,omitempty"`
}

type AuthScriptOutput struct {
	AccountName string `json:"accountName"`
	Success     bool   `json:"success"`
	Error       string `json:"error"`
}

type Jwt struct {
	Id       string `json:"id"`
	Expired  int    `json:"exp"`
	IssuedAt int    `json:"iat"`
	Issuer   string `json:"iss"`
}
type Config struct {
	JwkKeys string `json:"jwk_keys"`
	JwkUrl  string `json:"jwk_url"`
	JwkTTL  int    `json:"jwk_ttl"`
	AuthUrl string `json:"auth_url"`
}

func NewConfig() (config Config, err error) {
	if len(os.Args) < 2 {
		return
	}
	configFile, err := os.Open(os.Args[1])
	if err != nil {
		return
	}
	defer configFile.Close()
	configBytes, _ := io.ReadAll(configFile)
	err = json.Unmarshal(configBytes, &config)
	if err != nil {
		return
	}
	return config, nil
}

type Jwks struct {
	keys jose.JSONWebKeySet
}

func NewJwks(data []byte) (*Jwks, error) {
	keys := jose.JSONWebKeySet{}
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, err
	}
	return &Jwks{keys: keys}, nil
}

func (j *Jwks) verify(token string) (bool, error) {
	jws, err := jose.ParseSigned(token)
	if err != nil {
		return false, err
	}
	data, err := jws.Verify(j.keys)
	if err != nil {
		return false, err
	}
	jwt := Jwt{}
	if err := json.Unmarshal(data, &jwt); err != nil {
		return false, err
	}
	if time.Now().Unix() > int64(jwt.Expired) {
		return false, errors.New("token expred")
	}
	return true, nil
}

type JwksCache struct {
	keys *Jwks
}

func NewJwksCache(data []byte) (*JwksCache, error) {
	keys, err := NewJwks(data)
	if err != nil {
		return nil, err
	}
	return &JwksCache{keys: keys}, nil
}

func output(success bool) {
	var output AuthScriptOutput

	if success {
		output.Success = true
	} else {
		output.Success = false
		output.Error = ErrAuthFailed.Error()
	}
	message, err := json.Marshal(output)
	if err != nil {
		return
	}
	message = append(message, '\n')
	os.Stdout.Write(message)
}

func readUser() (input *AuthScriptInput, err error) {
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(line, &input)
	if err != nil {
		return nil, err
	}
	if input.AccountName == "" || input.Passphrase == "" {
		return nil, errors.New("AccountName/Passphrase cannot be empty")
	}
	return input, nil
}

func main() {
	config, err := NewConfig()
	if err != nil {
		panic(err)
	}
	jwks, err := NewJwks([]byte(config.JwkKeys))
	if err != nil {
		panic(err)
	}
	input, err := readUser()
	if err != nil {
		panic(err)
	}
	success, err := jwks.verify(input.Passphrase)
	if err != nil {
		panic(err)
	}
	output(success)
}
