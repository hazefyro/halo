package stateless_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hazefyro/halo/session"
	"github.com/hazefyro/halo/session/store/stateless"
)

var signingKey = []byte("test-signing-key")

func newStore(t *testing.T, opts ...stateless.Option) *stateless.Store {
	t.Helper()
	allOpts := append([]stateless.Option{stateless.WithSigningKey(signingKey)}, opts...)
	store, err := stateless.New(allOpts...)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return store
}

func testSession(now time.Time) *session.Session {
	return &session.Session{
		ID:         "raw-session-id",
		UserID:     "user-1",
		CreatedAt:  now,
		ExpiresAt:  now.Add(time.Hour),
		LastSeenAt: now.Add(5 * time.Minute),
	}
}

func TestNewRequiresSigningKey(t *testing.T) {
	store, err := stateless.New()
	if !errors.Is(err, session.ErrMissingSigningKey) {
		t.Fatalf("New() error = %v, want %v", err, session.ErrMissingSigningKey)
	}
	if store != nil {
		t.Fatalf("New() store = %#v, want nil", store)
	}
}

func TestNewRejectsInvalidTTL(t *testing.T) {
	store, err := stateless.New(stateless.WithSigningKey(signingKey), stateless.WithTTL(0))
	if !errors.Is(err, session.ErrInvalidTTL) {
		t.Fatalf("New() error = %v, want %v", err, session.ErrInvalidTTL)
	}
	if store != nil {
		t.Fatalf("New() store = %#v, want nil", store)
	}
}

func TestStoreTTL(t *testing.T) {
	store := newStore(t, stateless.WithTTL(30*time.Minute))
	if got := store.TTL(); got != 30*time.Minute {
		t.Fatalf("TTL() = %v, want %v", got, 30*time.Minute)
	}
}

func TestStoreSaveNoop(t *testing.T) {
	store := newStore(t)
	if err := store.Save(context.Background(), testSession(time.Now())); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
}

func TestStoreDeleteNoop(t *testing.T) {
	store := newStore(t)
	if err := store.Delete(context.Background(), "session-token"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
}

func TestStoreEncodeAndGetRoundTrip(t *testing.T) {
	now := time.Date(2099, 5, 31, 12, 0, 0, 0, time.UTC)
	store := newStore(t, stateless.WithIssuer("auth-test"))
	want := testSession(now)

	token, err := store.Encode(want)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	got, err := store.Get(context.Background(), session.SessionID(token))
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	if got.ID != want.ID || got.UserID != want.UserID {
		t.Fatalf("session identity = %#v, want %#v", got, want)
	}
	if !got.CreatedAt.Equal(want.CreatedAt) {
		t.Fatalf("CreatedAt = %v, want %v", got.CreatedAt, want.CreatedAt)
	}
	if !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Fatalf("ExpiresAt = %v, want %v", got.ExpiresAt, want.ExpiresAt)
	}
	if !got.LastSeenAt.Equal(want.LastSeenAt) {
		t.Fatalf("LastSeenAt = %v, want %v", got.LastSeenAt, want.LastSeenAt)
	}
}

func TestStoreGetRejectsInvalidToken(t *testing.T) {
	store := newStore(t)
	_, err := store.Get(context.Background(), "not-a-token")
	if !errors.Is(err, session.ErrInvalidSession) {
		t.Fatalf("Get() error = %v, want %v", err, session.ErrInvalidSession)
	}
}

func TestStoreGetRejectsWrongIssuer(t *testing.T) {
	now := time.Now()
	issuerStore := newStore(t, stateless.WithIssuer("issuer-a"))
	token, err := issuerStore.Encode(testSession(now))
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	store := newStore(t, stateless.WithIssuer("issuer-b"))
	_, err = store.Get(context.Background(), session.SessionID(token))
	if !errors.Is(err, session.ErrInvalidSession) {
		t.Fatalf("Get() error = %v, want %v", err, session.ErrInvalidSession)
	}
}

func TestStoreGetRejectsExpiredToken(t *testing.T) {
	now := time.Now().Add(-2 * time.Hour)
	store := newStore(t)
	token, err := store.Encode(testSession(now))
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	_, err = store.Get(context.Background(), session.SessionID(token))
	if !errors.Is(err, session.ErrInvalidSession) {
		t.Fatalf("Get() error = %v, want %v", err, session.ErrInvalidSession)
	}
}

func TestStoreGetRejectsUnexpectedSigningMethod(t *testing.T) {
	now := time.Now().Add(time.Hour)
	claims := stateless.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "raw-session-id",
			Issuer:    "session",
			ExpiresAt: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now.Add(-time.Hour)),
		},
		UserID:     "user-1",
		CreatedAt:  now.Add(-time.Hour).Unix(),
		LastSeenAt: now.Add(-time.Minute).Unix(),
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}

	store := newStore(t)
	_, err = store.Get(context.Background(), session.SessionID(token))
	if !errors.Is(err, session.ErrInvalidSession) {
		t.Fatalf("Get() error = %v, want %v", err, session.ErrInvalidSession)
	}
}

func TestStoreTouchUpdatesSessionTimes(t *testing.T) {
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	store := newStore(t, stateless.WithTTL(30*time.Minute))
	sess := testSession(now.Add(-time.Hour))

	if err := store.Touch(context.Background(), sess, now); err != nil {
		t.Fatalf("Touch() error = %v", err)
	}
	if !sess.LastSeenAt.Equal(now) {
		t.Fatalf("LastSeenAt = %v, want %v", sess.LastSeenAt, now)
	}
	if want := now.Add(30 * time.Minute); !sess.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt = %v, want %v", sess.ExpiresAt, want)
	}
}
