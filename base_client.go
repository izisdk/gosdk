package gosdk

import (
	"crawler.club/dl"
	"fmt"
)

var (
	defaultHeaderKeys = []string{"Content-Length", "Content-Type", "Content-MD5", "Credit-.*"}
)

type Client struct {
	Ak string
	Sk string
}

func NewClient(ak, sk string) *Client {
	return &Client{ak, sk}
}

func (c *Client) Request(url string, data interface{}) (string, error) {
	var err error
	if url, err = genUrl(url, nil); err != nil {
		return "", err
	}

	var body []byte
	if body, err = genBody(data); err != nil {
		return "", err
	}
	headers := genHeaders(body, nil)

	var msg string
	if msg, err = genMsg("POST", url, body, headers); err != nil {
		return "", err
	}

	authPrefix := genAuthPrefix(c.Ak)
	signKey := genSignKey(c.Sk, authPrefix)
	signature := genSignature(signKey, msg)
	headers["Authorization"] = fmt.Sprintf("%s//%s", authPrefix, signature)

	req := &dl.HttpRequest{
		Url:      url,
		Method:   "POST",
		PostData: string(body),
		UseProxy: false,
		Timeout:  60,
		Header:   headers,
		Retry:    1,
	}

	resp := dl.Download(req)
	if resp.Error != nil {
		return "", resp.Error
	}
	return resp.Text, nil
}
