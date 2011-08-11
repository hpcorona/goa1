package goa1

import "fmt"
import "os"
import "sort"
import "crypto/hmac"
import "hash"
import "encoding/base64"
import "http"
import "strings"

type OAuthRequest struct {
	Method						string
	URL								string
	ConsumerKey				string
	Token							string
	Nonce							string
	Timestamp					string
	SignatureMethod		string
	Version						string
	Signature					string
	Parameters				map[string][]string
}

func ParseRequest(r *http.Request) (*OAuthRequest, os.Error) {
	urladd := r.URL.String()
	idxq := strings.Index(urladd, "?")
	if idxq >= 0 {
		urladd = urladd[:idxq]
	}
	
	req := &OAuthRequest {
		Method: r.Method,
		URL: urladd,
		Parameters: make(map[string][]string),
	}
	
	for k, v := range r.Header {
		appendParam(req, k, v, false)
	}

	for k, v := range r.Form {
		appendParam(req, k, v, true)
	}

	for k, v := range r.URL.Query() {
		appendParam(req, k, v, true)
	}
	
	return req, nil
}

func appendParam(req *OAuthRequest, k string, value []string, add bool) {
	if len(value) == 0 {
		return
	}
	
	switch k {
		case "oauth_timestamp":
			req.Timestamp = value[0]
		case "oauth_version":
			req.Version = value[0]
		case "oauth_signature":
			req.Signature = value[0]
		case "oauth_consumer_key":
			req.ConsumerKey = value[0]
		case "oauth_nonce":
			req.Nonce = value[0]
		case "oauth_signature_method":
			req.SignatureMethod = value[0]
		default:
			if add {
				req.Parameters[k] = value
			}
	}
}

type StringSlice []string

func (arr StringSlice) Len() int {
	return len(arr)
}

func (arr StringSlice) Less(i, j int) bool {
	return arr[i] < arr[j]
}

func (arr StringSlice) Swap(i, j int) {
	v := arr[i]
	arr[i] = arr[j]
	arr[j] = v
}

func Validate(req *OAuthRequest, clientsecret, tokensecret string) (bool, os.Error) {
	params := make(map[string][]string)
	params["oauth_consumer_key"] = []string{req.ConsumerKey}
	params["oauth_nonce"] = []string{req.Nonce}
	params["oauth_signature_method"] = []string{req.SignatureMethod}
	params["oauth_timestamp"] = []string{req.Timestamp}
	params["oauth_token"] = []string{req.Token}
	params["oauth_version"] = []string{req.Version}
	
	for k, v := range req.Parameters {
		params[k] = v
	}
	
	total := len(params)
	ordered := make(StringSlice, 0, total)
	for k, _ := range params {
		ordered = append(ordered, k)
	}
	
	sort.Sort(ordered)
	
	parQry := ""
	for i := 0; i < total; i++ {
		vs := params[ordered[i]]
		for j := 0; j < len(vs); j++ {
			if len(parQry) > 0 {
				parQry = fmt.Sprintf("%s%%26%s%%3D%s", parQry, escape(ordered[i]), escape(vs[j]))
			} else {
				parQry = fmt.Sprintf("&%s%%3D%s", escape(ordered[i]), escape(vs[j]))
			}
		}
	}
	
	query := fmt.Sprintf("%s&%s%s", req.Method, escape(req.URL), parQry)

	key := fmt.Sprintf("%s&%s", escape(clientsecret), escape(tokensecret))
	sigbytes, err := sign(key, query, req.SignatureMethod)
	if err != nil {
		return false, err
	}

	signature := base(sigbytes)
	
	return signature == req.Signature, nil
}

func sign(key string, str string, method string) ([]byte, os.Error) {
	var hash hash.Hash
	
	if method == "HMAC-SHA1" {
		hash = hmac.NewSHA1([]byte(key))
	} else {
		return nil, os.NewError(fmt.Sprintf("Unsupported signature method: %s", method))
	}
	
	hash.Write([]byte(str))
	
	return hash.Sum(), nil
}

func base(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func escape(str string) string {
	str = http.URLEscape(str)
	str = strings.Replace(str, ":", "%3A", -1)
	str = strings.Replace(str, "/", "%2F", -1)
	
	return str
}
