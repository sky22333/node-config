package urlutil

import (
	"fmt"
	"net/url"
	"strings"
)

// ParseHTTPStyle parses scheme://... as http URL (OkHttp-style used in NekoBox).
func ParseHTTPStyle(raw, scheme string) (*url.URL, error) {
	u, err := url.Parse(strings.Replace(raw, scheme+"://", "http://", 1))
	if err != nil {
		return nil, err
	}
	if u.Host == "" {
		return nil, fmt.Errorf("missing host")
	}
	return u, nil
}

// FragmentName returns URL fragment decoded as profile name.
func FragmentName(u *url.URL) string {
	if u.Fragment == "" {
		return ""
	}
	name, _ := url.QueryUnescape(u.Fragment)
	return name
}
