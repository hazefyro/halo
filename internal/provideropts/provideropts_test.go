package provideropts_test

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/hazefyro/auth/internal/provideropts"
	"golang.org/x/oauth2"
)

func TestApplyAppliesOptionsInOrder(t *testing.T) {
	cfg := provideropts.Apply([]provideropts.Option{
		provideropts.WithScopes("first"),
		provideropts.WithScopes("second"),
		provideropts.WithAdditionalScopes("extra"),
	})
	if !reflect.DeepEqual(cfg.Scopes, []string{"second"}) {
		t.Fatalf("Scopes = %#v, want second", cfg.Scopes)
	}
	if !reflect.DeepEqual(cfg.AdditionalScopes, []string{"extra"}) {
		t.Fatalf("AdditionalScopes = %#v, want extra", cfg.AdditionalScopes)
	}
}

func TestWithScopesStoresScopes(t *testing.T) {
	cfg := provideropts.Apply([]provideropts.Option{provideropts.WithScopes("one", "two")})
	if !reflect.DeepEqual(cfg.Scopes, []string{"one", "two"}) {
		t.Fatalf("Scopes = %#v", cfg.Scopes)
	}
}

func TestWithAdditionalScopesStoresAdditionalScopes(t *testing.T) {
	cfg := provideropts.Apply([]provideropts.Option{provideropts.WithAdditionalScopes("one"), provideropts.WithAdditionalScopes("two")})
	if !reflect.DeepEqual(cfg.AdditionalScopes, []string{"one", "two"}) {
		t.Fatalf("AdditionalScopes = %#v", cfg.AdditionalScopes)
	}
}

func TestWithAuthCodeOptionsStoresOptions(t *testing.T) {
	opt := oauth2.SetAuthURLParam("prompt", "consent")
	cfg := provideropts.Apply([]provideropts.Option{provideropts.WithAuthCodeOptions(opt)})
	if len(cfg.AuthCodeOptions) != 1 {
		t.Fatalf("AuthCodeOptions len = %d, want 1", len(cfg.AuthCodeOptions))
	}
}

func TestWithHTTPClientStoresClient(t *testing.T) {
	client := &http.Client{}
	cfg := provideropts.Apply([]provideropts.Option{provideropts.WithHTTPClient(client)})
	if cfg.HTTPClient != client {
		t.Fatal("HTTPClient was not stored")
	}
}

func TestWithUserInfoURLStoresURL(t *testing.T) {
	cfg := provideropts.Apply([]provideropts.Option{provideropts.WithUserInfoURL("https://example.com/userinfo")})
	if cfg.UserInfoURL != "https://example.com/userinfo" {
		t.Fatalf("UserInfoURL = %q", cfg.UserInfoURL)
	}
}

func TestWithEndpointStoresEndpoint(t *testing.T) {
	endpoint := oauth2.Endpoint{AuthURL: "https://example.com/auth", TokenURL: "https://example.com/token"}
	cfg := provideropts.Apply([]provideropts.Option{provideropts.WithEndpoint(endpoint)})
	if cfg.Endpoint == nil || *cfg.Endpoint != endpoint {
		t.Fatalf("Endpoint = %#v, want %#v", cfg.Endpoint, endpoint)
	}
}
