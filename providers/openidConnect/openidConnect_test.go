package openidConnect

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/markbates/goth"
	"github.com/stretchr/testify/assert"
)

var (
	server *httptest.Server
)

func init() {
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// return the value of Google's setup at https://accounts.google.com/.well-known/openid-configuration
		_, _ = fmt.Fprintln(w, "{ \"issuer\": \"https://accounts.google.com\", \"authorization_endpoint\": \"https://accounts.google.com/o/oauth2/v2/auth\", \"token_endpoint\": \"https://www.googleapis.com/oauth2/v4/token\", \"userinfo_endpoint\": \"https://www.googleapis.com/oauth2/v3/userinfo\", \"revocation_endpoint\": \"https://accounts.google.com/o/oauth2/revoke\", \"jwks_uri\": \"https://www.googleapis.com/oauth2/v3/certs\", \"response_types_supported\": [ \"code\", \"token\", \"id_token\", \"code token\", \"code id_token\", \"token id_token\", \"code token id_token\", \"none\" ], \"subject_types_supported\": [ \"public\" ], \"id_token_signing_alg_values_supported\": [ \"RS256\" ], \"scopes_supported\": [ \"openid\", \"email\", \"profile\" ], \"token_endpoint_auth_methods_supported\": [ \"client_secret_post\", \"client_secret_basic\" ], \"claims_supported\": [ \"aud\", \"email\", \"email_verified\", \"exp\", \"family_name\", \"given_name\", \"iat\", \"iss\", \"locale\", \"name\", \"picture\", \"sub\" ], \"code_challenge_methods_supported\": [ \"plain\", \"S256\" ] }")
	}))
}

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := openidConnectProvider()
	a.Equal(os.Getenv("OPENID_CONNECT_KEY"), provider.ClientKey)
	a.Equal(os.Getenv("OPENID_CONNECT_SECRET"), provider.Secret)
	a.Equal("http://localhost/foo", provider.CallbackURL)

	a.Equal("https://accounts.google.com", provider.OpenIDConfig.Issuer)
	a.Equal("https://accounts.google.com/o/oauth2/v2/auth", provider.OpenIDConfig.AuthEndpoint)
	a.Equal("https://www.googleapis.com/oauth2/v4/token", provider.OpenIDConfig.TokenEndpoint)
	a.Equal("https://www.googleapis.com/oauth2/v3/userinfo", provider.OpenIDConfig.UserInfoEndpoint)
}

func Test_NewCustomisedURL(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider, _ := NewCustomisedURL(
		os.Getenv("OPENID_CONNECT_KEY"),
		os.Getenv("OPENID_CONNECT_SECRET"),
		"http://localhost/foo",
		"https://accounts.google.com/o/oauth2/v2/auth",
		"https://www.googleapis.com/oauth2/v4/token",
		"https://accounts.google.com",
		"https://www.googleapis.com/oauth2/v3/userinfo",
		"",
		server.URL,
	)
	a.Equal(os.Getenv("OPENID_CONNECT_KEY"), provider.ClientKey)
	a.Equal(os.Getenv("OPENID_CONNECT_SECRET"), provider.Secret)
	a.Equal("http://localhost/foo", provider.CallbackURL)

	a.Equal("https://accounts.google.com", provider.OpenIDConfig.Issuer)
	a.Equal("https://accounts.google.com/o/oauth2/v2/auth", provider.OpenIDConfig.AuthEndpoint)
	a.Equal("https://www.googleapis.com/oauth2/v4/token", provider.OpenIDConfig.TokenEndpoint)
	a.Equal("https://www.googleapis.com/oauth2/v3/userinfo", provider.OpenIDConfig.UserInfoEndpoint)
	a.Equal("", provider.OpenIDConfig.EndSessionEndpoint)
	a.Equal("openid-connect", provider.Name())
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := openidConnectProvider()
	session, err := provider.BeginAuth("test_state")
	s := session.(*Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "https://accounts.google.com/o/oauth2/v2/auth")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("OPENID_CONNECT_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "redirect_uri=http%3A%2F%2Flocalhost%2Ffoo")
	a.Contains(s.AuthURL, "scope=openid")
}

func Test_BeginAuth_AuthCodeOptions(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := openidConnectProvider()
	provider.SetAuthCodeOptions(map[string]string{"domain_hint": "test_domain.com", "prompt": "none"})
	session, err := provider.BeginAuth("test_state")
	s := session.(*Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "https://accounts.google.com/o/oauth2/v2/auth")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("OPENID_CONNECT_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "redirect_uri=http%3A%2F%2Flocalhost%2Ffoo")
	a.Contains(s.AuthURL, "scope=openid")
	a.Contains(s.AuthURL, "domain_hint=test_domain.com")
	a.Contains(s.AuthURL, "prompt=none")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	a.Implements((*goth.Provider)(nil), openidConnectProvider())
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := openidConnectProvider()

	s, err := provider.UnmarshalSession(`{"AuthURL":"https://accounts.google.com/o/oauth2/v2/auth","AccessToken":"1234567890","IDToken":"abc"}`)
	a.NoError(err)
	session := s.(*Session)
	a.Equal("https://accounts.google.com/o/oauth2/v2/auth", session.AuthURL)
	a.Equal("1234567890", session.AccessToken)
	a.Equal("abc", session.IDToken)
}

func Test_Implements_LogoutProvider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider, _ := NewCustomisedURL(
		"client_id",
		"client_secret",
		"http://localhost/callback",
		"https://example.com/auth",
		"https://example.com/token",
		"https://example.com",
		"https://example.com/userinfo",
		"https://example.com/logout",
	)
	a.Implements((*goth.LogoutProvider)(nil), provider)
}

func Test_EndSessionURL(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider, _ := NewCustomisedURL(
		"client_id",
		"client_secret",
		"http://localhost/callback",
		"https://example.com/auth",
		"https://example.com/token",
		"https://example.com",
		"https://example.com/userinfo",
		"https://example.com/logout",
	)

	// With all parameters
	logoutURL, err := provider.EndSessionURL("id_token_value", "http://localhost/post-logout", "some_state")
	a.NoError(err)
	a.Contains(logoutURL, "https://example.com/logout")
	a.Contains(logoutURL, "id_token_hint=id_token_value")
	a.Contains(logoutURL, "post_logout_redirect_uri="+url.QueryEscape("http://localhost/post-logout"))
	a.Contains(logoutURL, "state=some_state")
	a.NotContains(logoutURL, "client_id=")

	// Without id_token_hint, should include client_id
	logoutURL, err = provider.EndSessionURL("", "http://localhost/post-logout", "")
	a.NoError(err)
	a.Contains(logoutURL, "client_id=client_id")
	a.NotContains(logoutURL, "id_token_hint=")
	a.NotContains(logoutURL, "state=")

	// With only id_token_hint
	logoutURL, err = provider.EndSessionURL("id_token_value", "", "")
	a.NoError(err)
	a.Contains(logoutURL, "id_token_hint=id_token_value")
	a.NotContains(logoutURL, "post_logout_redirect_uri=")
}

func Test_EndSessionURL_MissingRPIdentifier(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	// Provider with empty client key and no id_token_hint
	provider, _ := NewCustomisedURL(
		"", // empty client key
		"client_secret",
		"http://localhost/callback",
		"https://example.com/auth",
		"https://example.com/token",
		"https://example.com",
		"https://example.com/userinfo",
		"https://example.com/logout",
	)

	_, err := provider.EndSessionURL("", "http://localhost/post-logout", "")
	a.Error(err)
	a.Contains(err.Error(), "missing RP identifier")

	// With id_token_hint it should still work even without client_id
	logoutURL, err := provider.EndSessionURL("id_token_value", "", "")
	a.NoError(err)
	a.Contains(logoutURL, "id_token_hint=id_token_value")
}

func Test_EndSessionURL_NoEndpoint(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	// Provider without end_session_endpoint
	provider := openidConnectProvider()
	_, err := provider.EndSessionURL("id_token", "http://localhost", "state")
	a.Error(err)
	a.Contains(err.Error(), "does not support RP-Initiated Logout")
}

func Test_GetOpenIDConfig_RejectsOversizedResponse(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	// Create a server that returns a response larger than maxResponseSize
	bigServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Write 2MB of data (exceeds 1MB limit)
		w.Header().Set("Content-Type", "application/json")
		data := make([]byte, 2<<20)
		for i := range data {
			data[i] = 'x'
		}
		_, _ = w.Write(data)
	}))
	defer bigServer.Close()

	p := &Provider{HTTPClient: bigServer.Client()}
	_, err := getOpenIDConfig(context.Background(), p, bigServer.URL)
	a.ErrorContains(err, "http: request body too large")
}

func Test_ValidateClaims_MissingExp(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := openidConnectProvider()

	claims := map[string]interface{}{
		"aud": os.Getenv("OPENID_CONNECT_KEY"),
		"iss": "https://accounts.google.com",
	}
	_, err := provider.validateClaims(claims)
	a.EqualError(err, "missing required exp claim in token")
}

func Test_ValidateClaims_InvalidExpType(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := openidConnectProvider()

	claims := map[string]interface{}{
		"aud": os.Getenv("OPENID_CONNECT_KEY"),
		"iss": "https://accounts.google.com",
		"exp": "not-a-number",
	}
	_, err := provider.validateClaims(claims)
	a.EqualError(err, "invalid exp claim type in token")
}

func Test_GetUserInfo_PreservesIDTokenClaims(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	// Mock UserInfo endpoint that returns claims that differ from the ID token
	userInfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `{"sub":"user123","email":"eve@evil.com","picture":"https://pic.url"}`)
	}))
	defer userInfoServer.Close()

	provider, err := NewCustomisedURL(
		"client_id", "client_secret", "http://localhost/callback",
		"https://example.com/auth", "https://example.com/token",
		"https://example.com", userInfoServer.URL, "",
	)
	a.NoError(err)

	// Simulate ID token claims with email already set
	claims := map[string]interface{}{
		"sub":   "user123",
		"email": "alice@idp.com",
	}

	err = provider.getUserInfo("fake-access-token", claims)
	a.NoError(err)

	// ID token email should be preserved, not overwritten by UserInfo
	a.Equal("alice@idp.com", claims["email"])
	// But new claims from UserInfo should be added
	a.Equal("https://pic.url", claims["picture"])
}

func openidConnectProvider() *Provider {
	provider, _ := New(os.Getenv("OPENID_CONNECT_KEY"), os.Getenv("OPENID_CONNECT_SECRET"), "http://localhost/foo", server.URL)
	return provider
}

// countingTransport counts the round trips that pass through a client.
type countingTransport struct {
	count atomic.Int32
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.count.Add(1)
	return http.DefaultTransport.RoundTrip(r)
}

func Test_NewCustomisedHttpClientContext_UsesClientForDiscovery(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	transport := &countingTransport{}
	client := &http.Client{Transport: transport}

	provider, err := NewCustomisedHttpClientContext(context.Background(), client, "", "key", "secret", "http://localhost/foo", server.URL)
	a.NoError(err)
	a.Equal(int32(1), transport.count.Load())
	a.Same(client, provider.HTTPClient)
	a.Equal("openid-connect", provider.Name())
	a.Equal("https://accounts.google.com", provider.OpenIDConfig.Issuer)

	named, err := NewCustomisedHttpClient(client, "Foo", "key", "secret", "http://localhost/foo", server.URL)
	a.NoError(err)
	a.Equal(int32(2), transport.count.Load())
	a.Same(client, named.HTTPClient)
	a.Equal("foo-oidc", named.Name())
}

func Test_NewCustomisedHttpClientContext_StopsDiscovery(t *testing.T) {
	t.Parallel()

	const returnBound = 5 * time.Second

	tests := []struct {
		name   string
		client *http.Client
		ctx    func() (context.Context, context.CancelFunc)
		check  func(a *assert.Assertions, err error)
	}{
		{
			name:   "cancelled context",
			client: &http.Client{},
			ctx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				time.AfterFunc(50*time.Millisecond, cancel)
				return ctx, cancel
			},
			check: func(a *assert.Assertions, err error) { a.ErrorIs(err, context.Canceled) },
		},
		{
			name:   "context deadline",
			client: &http.Client{},
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 50*time.Millisecond)
			},
			check: func(a *assert.Assertions, err error) { a.ErrorIs(err, context.DeadlineExceeded) },
		},
		{
			name:   "client timeout",
			client: &http.Client{Timeout: 50 * time.Millisecond},
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
			check: func(a *assert.Assertions, err error) {
				var urlErr *url.Error
				a.True(errors.As(err, &urlErr) && urlErr.Timeout(), "expected a timeout error, got %v", err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a := assert.New(t)

			release := make(chan struct{})
			blocking := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case <-r.Context().Done():
				case <-release:
				}
			}))
			defer blocking.Close()
			defer close(release)

			ctx, cancel := tt.ctx()
			defer cancel()

			start := time.Now()
			provider, err := NewCustomisedHttpClientContext(ctx, tt.client, "", "key", "secret", "http://localhost/foo", blocking.URL)
			a.Less(time.Since(start), returnBound)
			a.Nil(provider)
			a.Error(err)
			tt.check(a, err)
		})
	}
}

func Test_RefreshToken_UsesHTTPClient(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"access_token":"new-access","token_type":"Bearer","refresh_token":"new-refresh","expires_in":3600}`)
	}))
	defer tokenServer.Close()

	provider, err := NewCustomisedURL("key", "secret", "http://localhost/foo",
		"https://accounts.example.com/auth", tokenServer.URL, "https://accounts.example.com", "", "")
	a.NoError(err)

	transport := &countingTransport{}
	provider.HTTPClient = &http.Client{Transport: transport}

	token, err := provider.RefreshToken("r")
	a.NoError(err)
	a.Equal("new-access", token.AccessToken)
	a.Equal(int32(1), transport.count.Load())
}

func Test_NewCustomisedHttpClientContext_RejectsInvalidDiscoveryURL(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider, err := NewCustomisedHttpClientContext(context.Background(), nil, "", "key", "secret", "http://localhost/foo", "http://bad\x7furl/")
	a.Nil(provider)
	a.Error(err)
}
