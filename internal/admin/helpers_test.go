package admin_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func newServer(t *testing.T, h http.Handler) string {
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL
}
