package provideropts

import (
	"net/http"
	"reflect"
	"testing"

	"golang.org/x/oauth2"
)

func TestApplyAppliesOptionsInOrder(t *testing.T) {
	cfg := Apply([]Option{
		WithScopes("first"),
		WithScopes("second"),
		WithAdditionalScopes("extra"),
	})
	if !reflect.DeepEqual(cfg.Scopes, []string{"second"}) {
		t.Fatalf("Scopes = %#v, want second", cfg.Scopes)
	}
	if !reflect.DeepEqual(cfg.AdditionalScopes, []string{"extra"}) {
		t.Fatalf("AdditionalScopes = %#v, want extra", cfg.AdditionalScopes)
	}
}

func TestWithScopesStoresScopes(t *testing.T) {
	cfg := Apply([]Option{WithScopes("one", "two")})
	if !reflect.DeepEqual(cfg.Scopes, []string{"one", "two"}) {
		t.Fatalf("Scopes = %#v", cfg.Scopes)
	}
}

func TestWithAdditionalScopesStoresAdditionalScopes(t *testing.T) {
	cfg := Apply([]Option{WithAdditionalScopes("one"), WithAdditionalScopes("two")})
	if !reflect.DeepEqual(cfg.AdditionalScopes, []string{"one", "two"}) {
		t.Fatalf("AdditionalScopes = %#v", cfg.AdditionalScopes)
	}
}

func TestWithAuthCodeOptionsStoresOptions(t *testing.T) {
	opt := oauth2.SetAuthURLParam("prompt", "consent")
	cfg := Apply([]Option{WithAuthCodeOptions(opt)})
	if len(cfg.AuthCodeOptions) != 1 {
		t.Fatalf("AuthCodeOptions len = %d, want 1", len(cfg.AuthCodeOptions))
	}
}

func TestWithHTTPClientStoresClient(t *testing.T) {
	client := &http.Client{}
	cfg := Apply([]Option{WithHTTPClient(client)})
	if cfg.HTTPClient != client {
		t.Fatal("HTTPClient was not stored")
	}
}

func TestWithUserInfoURLStoresURL(t *testing.T) {
	cfg := Apply([]Option{WithUserInfoURL("https://example.com/userinfo")})
	if cfg.UserInfoURL != "https://example.com/userinfo" {
		t.Fatalf("UserInfoURL = %q", cfg.UserInfoURL)
	}
}

func TestWithEndpointStoresEndpoint(t *testing.T) {
	endpoint := oauth2.Endpoint{AuthURL: "https://example.com/auth", TokenURL: "https://example.com/token"}
	cfg := Apply([]Option{WithEndpoint(endpoint)})
	if cfg.Endpoint == nil || *cfg.Endpoint != endpoint {
		t.Fatalf("Endpoint = %#v, want %#v", cfg.Endpoint, endpoint)
	}
}
