package openidConnect

import (
	"testing"

	"github.com/markbates/goth"
	"github.com/stretchr/testify/assert"
)

func Test_Implements_Session(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &Session{}

	a.Implements((*goth.Session)(nil), s)
}

func Test_GetAuthURL(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &Session{}

	_, err := s.GetAuthURL()
	a.Error(err)

	s.AuthURL = "/foo"

	url, _ := s.GetAuthURL()
	a.Equal(url, "/foo")
}

func Test_ToJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &Session{}

	data := s.Marshal()
	a.Equal(data, `{"AuthURL":"","AccessToken":"","RefreshToken":"","ExpiresAt":"0001-01-01T00:00:00Z","IDToken":""}`)
}

func Test_String(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &Session{}

	a.Equal(s.String(), s.Marshal())
}

func Test_Authorize_RejectsRedirectURIMismatch(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := openidConnectProvider()
	s := &Session{
		AuthURL: "https://accounts.google.com/o/oauth2/v2/auth",
	}

	// Create params with a different redirect_uri
	params := mapParams{
		"code":         "test_code",
		"redirect_uri": "https://evil.example.com/callback",
	}

	_, err := s.Authorize(provider, params)
	a.Error(err)
	a.Contains(err.Error(), "redirect_uri")
}

// mapParams implements goth.Params for testing
type mapParams map[string]string

func (m mapParams) Get(key string) string {
	return m[key]
}
