package redis_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	"github.com/hazefyro/halo/session"
	redisstore "github.com/hazefyro/halo/session/store/redis"
)

func newTestStore(t *testing.T, opts ...redisstore.Option) (*redisstore.Store, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	// MaxRetries -1 makes calls fail fast once the server is closed, which the
	// error-path tests rely on.
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = client.Close() })

	allOpts := append([]redisstore.Option{redisstore.WithClient(client)}, opts...)
	store, err := redisstore.New(allOpts...)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return store, mr
}

func testSession() *session.Session {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	return &session.Session{
		ID:         "sess-123",
		UserID:     "user-1",
		CreatedAt:  now,
		ExpiresAt:  now.Add(time.Hour),
		LastSeenAt: now,
	}
}

func TestNewRequiresClient(t *testing.T) {
	store, err := redisstore.New()
	if !errors.Is(err, session.ErrNilClient) {
		t.Fatalf("New() error = %v, want %v", err, session.ErrNilClient)
	}
	if store != nil {
		t.Fatalf("New() store = %#v, want nil", store)
	}
}

func TestNewRejectsInvalidTTL(t *testing.T) {
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	store, err := redisstore.New(redisstore.WithClient(client), redisstore.WithTTL(0))
	if !errors.Is(err, session.ErrInvalidTTL) {
		t.Fatalf("New() error = %v, want %v", err, session.ErrInvalidTTL)
	}
	if store != nil {
		t.Fatalf("New() store = %#v, want nil", store)
	}
}

func TestSaveStoresSessionWithTTL(t *testing.T) {
	store, mr := newTestStore(t, redisstore.WithTTL(time.Hour))
	sess := testSession()

	if err := store.Save(context.Background(), sess); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	key := "sess:" + sess.ID.String()
	if _, err := mr.Get(key); err != nil {
		t.Fatalf("session not stored under %q: %v", key, err)
	}
	if ttl := mr.TTL(key); ttl != time.Hour {
		t.Fatalf("key TTL = %v, want %v", ttl, time.Hour)
	}
}

func TestSaveGetRoundTrip(t *testing.T) {
	store, _ := newTestStore(t)
	sess := testSession()

	if err := store.Save(context.Background(), sess); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	got, err := store.Get(context.Background(), sess.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.ID != sess.ID || got.UserID != sess.UserID ||
		!got.CreatedAt.Equal(sess.CreatedAt) || !got.ExpiresAt.Equal(sess.ExpiresAt) ||
		!got.LastSeenAt.Equal(sess.LastSeenAt) {
		t.Fatalf("Get() = %#v, want %#v", got, sess)
	}
}

func TestCustomKeyPrefix(t *testing.T) {
	store, mr := newTestStore(t, redisstore.WithKeyPrefix("halo:"))
	sess := testSession()

	if err := store.Save(context.Background(), sess); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if _, err := mr.Get("halo:" + sess.ID.String()); err != nil {
		t.Fatalf("session not stored under custom prefix: %v", err)
	}
}

func TestGetMissingReturnsNotFound(t *testing.T) {
	store, _ := newTestStore(t)
	_, err := store.Get(context.Background(), "missing")
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("Get() error = %v, want %v", err, session.ErrSessionNotFound)
	}
}

func TestGetCorruptedDataReturnsError(t *testing.T) {
	store, mr := newTestStore(t)
	mr.Set("sess:bad", "not-json")

	_, err := store.Get(context.Background(), "bad")
	if err == nil {
		t.Fatal("Get() error = nil, want unmarshal error")
	}
	if errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("Get() error = %v, want a non-NotFound decode error", err)
	}
}

func TestTouchUpdatesSessionAndResetsTTL(t *testing.T) {
	store, mr := newTestStore(t, redisstore.WithTTL(time.Hour))
	sess := testSession()
	if err := store.Save(context.Background(), sess); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Let part of the TTL elapse, then touch.
	mr.FastForward(30 * time.Minute)
	now := sess.CreatedAt.Add(45 * time.Minute)
	if err := store.Touch(context.Background(), sess, now); err != nil {
		t.Fatalf("Touch() error = %v", err)
	}

	if !sess.LastSeenAt.Equal(now) {
		t.Fatalf("LastSeenAt = %v, want %v", sess.LastSeenAt, now)
	}
	if want := now.Add(time.Hour); !sess.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt = %v, want %v", sess.ExpiresAt, want)
	}

	// The updated session must be persisted and readable back (regression: a
	// previous Touch passed the struct to Set instead of marshaled JSON).
	got, err := store.Get(context.Background(), sess.ID)
	if err != nil {
		t.Fatalf("Get() after Touch error = %v", err)
	}
	if !got.LastSeenAt.Equal(now) || !got.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("persisted session = %#v, want LastSeen/Expires updated", got)
	}

	// The key TTL must be reset to the full window.
	if ttl := mr.TTL("sess:" + sess.ID.String()); ttl != time.Hour {
		t.Fatalf("TTL after Touch = %v, want %v", ttl, time.Hour)
	}
}

func TestDeleteRemovesSession(t *testing.T) {
	store, _ := newTestStore(t)
	sess := testSession()
	if err := store.Save(context.Background(), sess); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	if err := store.Delete(context.Background(), sess.ID); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := store.Get(context.Background(), sess.ID); !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("Get() after Delete error = %v, want %v", err, session.ErrSessionNotFound)
	}
}

func TestDeleteMissingIsNoError(t *testing.T) {
	store, _ := newTestStore(t)
	if err := store.Delete(context.Background(), "missing"); err != nil {
		t.Fatalf("Delete() missing key error = %v, want nil", err)
	}
}

func TestExpiredKeyIsNotFound(t *testing.T) {
	store, mr := newTestStore(t, redisstore.WithTTL(time.Hour))
	sess := testSession()
	if err := store.Save(context.Background(), sess); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	mr.FastForward(2 * time.Hour) // past the TTL
	if _, err := store.Get(context.Background(), sess.ID); !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("Get() after expiry error = %v, want %v", err, session.ErrSessionNotFound)
	}
}

func TestEncodeReturnsSessionID(t *testing.T) {
	store, _ := newTestStore(t)
	got, err := store.Encode(&session.Session{ID: "abc"})
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if got != "abc" {
		t.Fatalf("Encode() = %q, want abc", got)
	}
}

func TestTTLReturnsConfiguredTTL(t *testing.T) {
	store, _ := newTestStore(t, redisstore.WithTTL(90*time.Minute))
	if got := store.TTL(); got != 90*time.Minute {
		t.Fatalf("TTL() = %v, want %v", got, 90*time.Minute)
	}
}

func TestSaveReturnsClientError(t *testing.T) {
	store, mr := newTestStore(t)
	mr.Close() // server gone -> connection error, not a redis.Nil miss

	if err := store.Save(context.Background(), testSession()); err == nil {
		t.Fatal("Save() error = nil, want client error")
	}
}

func TestGetReturnsClientError(t *testing.T) {
	store, mr := newTestStore(t)
	mr.Close()

	_, err := store.Get(context.Background(), "x")
	if err == nil {
		t.Fatal("Get() error = nil, want client error")
	}
	if errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("Get() error = %v, want a connection error not NotFound", err)
	}
}

func TestDeleteReturnsClientError(t *testing.T) {
	store, mr := newTestStore(t)
	mr.Close()

	if err := store.Delete(context.Background(), "x"); err == nil {
		t.Fatal("Delete() error = nil, want client error")
	}
}
