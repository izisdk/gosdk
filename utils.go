package gosdk

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

func encrypt(sk, msg []byte) string {
	hash := hmac.New(sha256.New, sk)
	hash.Write(msg)
	return hex.EncodeToString(hash.Sum(nil))
}

func genUrl(srcUrl string, params map[string]string) (string, error) {
	if params == nil {
		params = make(map[string]string)
	}
	urlObj, err := url.Parse(srcUrl)
	if err != nil {
		return "", err
	}
	var keys []string
	urlVals, err := url.ParseQuery(urlObj.RawQuery)
	if err != nil {
		return "", err
	}
	for k, _ := range urlVals {
		params[k] = urlVals.Get(k)
	}
	for k, _ := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var query string
	for i, k := range keys {
		if i != 0 {
			query += "&"
		}
		query += k + "=" + url.QueryEscape(urlVals.Get(k))
	}
	urlObj.RawQuery = query
	return urlObj.String(), nil
}

func genBody(data interface{}) ([]byte, error) {
	var body []byte
	switch data.(type) {
	case map[string]string:
		d := url.Values{}
		for k, v := range data.(map[string]string) {
			d.Set(k, v)
		}
		body = []byte(d.Encode())
	case string:
		body = []byte(data.(string))
	case []byte:
		body = data.([]byte)
	default:
		return nil, errors.New("invalid data format, only support map or string")
	}
	return body, nil
}

func genHeaders(body []byte, headers map[string]string) map[string]string {
	if headers == nil {
		headers = make(map[string]string)
	}
	headers["Content-Length"] = fmt.Sprintf("%d", len(body))
	h := md5.New()
	h.Write(body)
	headers["Content-MD5"] = hex.EncodeToString(h.Sum(nil))
	headers["Content-Type"] = "application/x-www-form-urlencoded"
	return headers
}

func genMsg(method, srcUrl string, body []byte, headers map[string]string) (string, error) {
	var msg string
	// Method
	msg += method + "\n"

	urlObj, err := url.Parse(srcUrl)
	if err != nil {
		return "", err
	}
	// URI
	msg += urlObj.Path + "\n"

	// Query
	var keys []string
	urlVals, err := url.ParseQuery(urlObj.RawQuery)
	if err != nil {
		return "", err
	}
	for k, _ := range urlVals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var query string
	for i, k := range keys {
		if i != 0 {
			query += "&"
		}
		query += k + "=" + url.QueryEscape(urlVals.Get(k))
	}
	msg += query + "\n"

	// Headers
	encHeaderKeys := []string{"Content-Length", "Content-Type", "Content-MD5"}
	for k, _ := range headers {
		if strings.Contains(k, "credit-") {
			encHeaderKeys = append(encHeaderKeys, k)
		}
	}
	sort.Strings(encHeaderKeys)
	for _, k := range encHeaderKeys {
		val := url.QueryEscape(strings.TrimSpace(headers[k]))
		msg += strings.ToLower(k) + ":" + val + "\n"
	}
	msg = strings.TrimSpace(msg)
	return msg, nil
}

func genAuthPrefix(ak string) string {
	version := 1
	expire := 1800
	ts := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	return fmt.Sprintf("credit-v%d/%s/%s/%d", version, ak, ts, expire)
}

func genSignKey(sk, authPrefix string) string {
	return encrypt([]byte(sk), []byte(authPrefix))
}

func genSignature(signKey, msg string) string {
	return encrypt([]byte(signKey), []byte(msg))
}
