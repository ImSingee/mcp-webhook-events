package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// OAuth grant errors, told apart so the token endpoint can answer each.
var (
	ErrExpired = errors.New("expired")
	ErrRevoked = errors.New("revoked")
	// ErrReplay is a refresh token or authorization code used a second
	// time; the grant it came from has been revoked.
	ErrReplay = errors.New("replayed")
)

// Client is an OAuth client registered by RFC 7591 dynamic registration.
type Client struct {
	ID              string
	SecretHash      string // "" for a public client
	Name            string
	RedirectURIs    []string
	TokenAuthMethod string // none, client_secret_post or client_secret_basic
	GrantTypes      []string
	CreatedAt       time.Time
}

// CreateClient registers a client.
func (s *Store) CreateClient(ctx context.Context, c Client) error {
	uris, _ := json.Marshal(c.RedirectURIs)
	grants, _ := json.Marshal(c.GrantTypes)
	var secret any
	if c.SecretHash != "" {
		secret = c.SecretHash
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, redirect_uris, token_endpoint_auth_method, grant_types, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		c.ID, secret, c.Name, string(uris), c.TokenAuthMethod, string(grants), c.CreatedAt.UnixMilli())
	return err
}

// GetClient is the client with that id.
func (s *Store) GetClient(ctx context.Context, id string) (Client, error) {
	var (
		c            Client
		secret       sql.NullString
		uris, grants string
		created      int64
	)
	err := s.db.QueryRowContext(ctx, `SELECT client_id, client_secret_hash, client_name, redirect_uris, token_endpoint_auth_method, grant_types, created_at FROM oauth_clients WHERE client_id = ?`, id).
		Scan(&c.ID, &secret, &c.Name, &uris, &c.TokenAuthMethod, &grants, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return Client{}, ErrNotFound
	}
	if err != nil {
		return Client{}, err
	}
	c.SecretHash = secret.String
	c.CreatedAt = at(created)
	_ = json.Unmarshal([]byte(uris), &c.RedirectURIs)
	_ = json.Unmarshal([]byte(grants), &c.GrantTypes)
	return c, nil
}

// AuthRequest is a validated authorization request waiting for the user's
// consent on the consent page.
type AuthRequest struct {
	ID            string
	ClientID      string
	RedirectURI   string
	State         string
	CodeChallenge string
	Scope         string
	Resource      string
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

// CreateAuthRequest stores a pending authorization request.
func (s *Store) CreateAuthRequest(ctx context.Context, r AuthRequest) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO oauth_requests (id, client_id, redirect_uri, state, code_challenge, scope, resource, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.ClientID, r.RedirectURI, r.State, r.CodeChallenge, r.Scope, r.Resource, r.CreatedAt.UnixMilli(), r.ExpiresAt.UnixMilli())
	return err
}

// GetAuthRequest is a pending request that hasn't expired.
func (s *Store) GetAuthRequest(ctx context.Context, id string) (AuthRequest, error) {
	var (
		r                AuthRequest
		created, expires int64
	)
	err := s.db.QueryRowContext(ctx, `SELECT id, client_id, redirect_uri, state, code_challenge, scope, resource, created_at, expires_at FROM oauth_requests WHERE id = ? AND expires_at > ?`, id, s.nowMS()).
		Scan(&r.ID, &r.ClientID, &r.RedirectURI, &r.State, &r.CodeChallenge, &r.Scope, &r.Resource, &created, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return AuthRequest{}, ErrNotFound
	}
	r.CreatedAt, r.ExpiresAt = at(created), at(expires)
	return r, err
}

// TakeAuthRequest deletes a pending request, reporting whether it was
// there: the request is answered once.
func (s *Store) TakeAuthRequest(ctx context.Context, id string) error {
	return affected(s.db.ExecContext(ctx, `DELETE FROM oauth_requests WHERE id = ? AND expires_at > ?`, id, s.nowMS()))
}

// Code is an authorization code, stored by hash.
type Code struct {
	Hash          string
	ClientID      string
	IdentityID    string
	RedirectURI   string
	CodeChallenge string
	Scope         string
	Resource      string
	ExpiresAt     time.Time
}

// CreateCode stores an authorization code.
func (s *Store) CreateCode(ctx context.Context, c Code) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO oauth_codes (code_hash, client_id, identity_id, redirect_uri, code_challenge, scope, resource, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.Hash, c.ClientID, c.IdentityID, c.RedirectURI, c.CodeChallenge, c.Scope, c.Resource, s.nowMS(), c.ExpiresAt.UnixMilli())
	return err
}

// Family is one authorization: the grant an approved consent made, which
// its access and refresh tokens belong to. Revoking it revokes them all.
type Family struct {
	ID          string
	IdentityID  string
	ClientID    string
	RedirectURI string
	Scope       string
	Resource    string
	CreatedAt   time.Time
	LastUsedAt  *time.Time
	RevokedAt   *time.Time
}

// Token is an access or refresh token, stored by hash.
type Token struct {
	Hash      string
	Kind      string // access or refresh
	ExpiresAt time.Time
}

func insertToken(ctx context.Context, tx *sql.Tx, familyID string, t Token, now int64) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO oauth_tokens (token_hash, kind, family_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`, t.Hash, t.Kind, familyID, now, t.ExpiresAt.UnixMilli())
	return err
}

func revokeFamily(ctx context.Context, tx *sql.Tx, id string, now int64) error {
	if _, err := tx.ExecContext(ctx, `UPDATE oauth_families SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, now, id); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE oauth_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL`, now, id)
	return err
}

// RedeemCode exchanges an authorization code for a new family and its
// first tokens. check sees the code first and refuses it with its own error
// (a wrong client, redirect URI, PKCE verifier or resource). A code used a
// second time revokes the family it was first exchanged for (OAuth 2.1
// §4.1.2) and is ErrReplay; ErrNotFound is an unknown code. The returned
// string is the id of the family that was revoked on a replay.
func (s *Store) RedeemCode(ctx context.Context, hash string, check func(Code) error, fam Family, tokens ...Token) (revoked string, err error) {
	now := s.nowMS()
	err = s.inTx(ctx, func(tx *sql.Tx) error {
		var (
			c       Code
			expires int64
			used    sql.NullInt64
			famID   sql.NullString
		)
		err := tx.QueryRowContext(ctx, `SELECT code_hash, client_id, identity_id, redirect_uri, code_challenge, scope, resource, expires_at, used_at, family_id FROM oauth_codes WHERE code_hash = ?`, hash).
			Scan(&c.Hash, &c.ClientID, &c.IdentityID, &c.RedirectURI, &c.CodeChallenge, &c.Scope, &c.Resource, &expires, &used, &famID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		c.ExpiresAt = at(expires)
		if used.Valid {
			revoked = famID.String
			return ErrReplay
		}
		if expires <= now {
			return ErrExpired
		}
		if err := check(c); err != nil {
			return err
		}
		fam.IdentityID, fam.ClientID, fam.RedirectURI, fam.Scope, fam.Resource = c.IdentityID, c.ClientID, c.RedirectURI, c.Scope, c.Resource
		if _, err := tx.ExecContext(ctx, `INSERT INTO oauth_families (id, identity_id, client_id, redirect_uri, scope, resource, created_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			fam.ID, fam.IdentityID, fam.ClientID, fam.RedirectURI, fam.Scope, fam.Resource, now, now); err != nil {
			return err
		}
		for _, t := range tokens {
			if err := insertToken(ctx, tx, fam.ID, t, now); err != nil {
				return err
			}
		}
		_, err = tx.ExecContext(ctx, `UPDATE oauth_codes SET used_at = ?, family_id = ? WHERE code_hash = ?`, now, fam.ID, hash)
		return err
	})
	if errors.Is(err, ErrReplay) && revoked != "" {
		// outside the rolled-back transaction, so the revocation sticks
		if rerr := s.inTx(ctx, func(tx *sql.Tx) error { return revokeFamily(ctx, tx, revoked, now) }); rerr != nil {
			return "", rerr
		}
	}
	return revoked, err
}

func scanFamily(sc interface{ Scan(...any) error }) (Family, error) {
	var (
		f             Family
		created       int64
		used, revoked sql.NullInt64
	)
	err := sc.Scan(&f.ID, &f.IdentityID, &f.ClientID, &f.RedirectURI, &f.Scope, &f.Resource, &created, &used, &revoked)
	f.CreatedAt, f.LastUsedAt, f.RevokedAt = at(created), ms(used), ms(revoked)
	return f, err
}

const familyCols = `f.id, f.identity_id, f.client_id, f.redirect_uri, f.scope, f.resource, f.created_at, f.last_used_at, f.revoked_at`

// RotateRefresh exchanges a refresh token for new tokens in the same
// family, marking the old one used. A refresh token used a second time
// revokes its whole family and is ErrReplay; check sees the family first
// and refuses it with its own error (another client, another resource).
func (s *Store) RotateRefresh(ctx context.Context, hash string, check func(Family) error, tokens ...Token) (Family, error) {
	now := s.nowMS()
	var (
		fam      Family
		replayed bool
	)
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var (
			expires       int64
			used, revoked sql.NullInt64
		)
		f, err := scanFamily(tx.QueryRowContext(ctx, `SELECT `+familyCols+` FROM oauth_tokens t JOIN oauth_families f ON f.id = t.family_id WHERE t.token_hash = ? AND t.kind = 'refresh'`, hash))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		fam = f
		if err := tx.QueryRowContext(ctx, `SELECT expires_at, used_at, revoked_at FROM oauth_tokens WHERE token_hash = ?`, hash).Scan(&expires, &used, &revoked); err != nil {
			return err
		}
		if f.RevokedAt != nil || revoked.Valid {
			return ErrRevoked
		}
		if used.Valid {
			replayed = true
			return ErrReplay
		}
		if expires <= now {
			return ErrExpired
		}
		if err := check(f); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE oauth_tokens SET used_at = ? WHERE token_hash = ?`, now, hash); err != nil {
			return err
		}
		for _, t := range tokens {
			if err := insertToken(ctx, tx, f.ID, t, now); err != nil {
				return err
			}
		}
		_, err = tx.ExecContext(ctx, `UPDATE oauth_families SET last_used_at = ? WHERE id = ?`, now, f.ID)
		return err
	})
	if replayed {
		if rerr := s.inTx(ctx, func(tx *sql.Tx) error { return revokeFamily(ctx, tx, fam.ID, now) }); rerr != nil {
			return fam, rerr
		}
	}
	return fam, err
}

// Grant is what a valid access token stands for.
type Grant struct {
	Family       Family
	IdentityName string
	ClientName   string
	ExpiresAt    time.Time
}

// LookupAccess is the grant of a live access token: not expired, and
// neither it nor its family revoked. ErrNotFound otherwise.
func (s *Store) LookupAccess(ctx context.Context, hash string) (Grant, error) {
	var (
		g       Grant
		expires int64
	)
	row := s.db.QueryRowContext(ctx, `SELECT `+familyCols+`, i.name, c.client_name, t.expires_at
FROM oauth_tokens t
JOIN oauth_families f ON f.id = t.family_id
JOIN identities i ON i.id = f.identity_id
JOIN oauth_clients c ON c.client_id = f.client_id
WHERE t.token_hash = ? AND t.kind = 'access' AND t.revoked_at IS NULL AND f.revoked_at IS NULL AND t.expires_at > ?`, hash, s.nowMS())
	var (
		created       int64
		used, revoked sql.NullInt64
	)
	err := row.Scan(&g.Family.ID, &g.Family.IdentityID, &g.Family.ClientID, &g.Family.RedirectURI, &g.Family.Scope, &g.Family.Resource, &created, &used, &revoked, &g.IdentityName, &g.ClientName, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return Grant{}, ErrNotFound
	}
	if err != nil {
		return Grant{}, err
	}
	g.Family.CreatedAt, g.Family.LastUsedAt, g.Family.RevokedAt = at(created), ms(used), ms(revoked)
	g.ExpiresAt = at(expires)
	return g, nil
}

// FamilyAlive reports whether a family exists and isn't revoked.
func (s *Store) FamilyAlive(ctx context.Context, id string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM oauth_families WHERE id = ? AND revoked_at IS NULL`, id).Scan(&n)
	return n > 0, err
}

// TouchFamily records that a family's token was just used.
func (s *Store) TouchFamily(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE oauth_families SET last_used_at = ? WHERE id = ?`, s.nowMS(), id)
	return err
}

// RevokeTokenByHash revokes a token presented to the revocation endpoint by
// clientID (RFC 7009): a refresh token revokes its family, an access token
// itself. It reports the family that was revoked, if one was; a token of
// another client, or none at all, changes nothing.
func (s *Store) RevokeTokenByHash(ctx context.Context, hash, clientID string) (family string, err error) {
	now := s.nowMS()
	err = s.inTx(ctx, func(tx *sql.Tx) error {
		var kind, fid, cid string
		err := tx.QueryRowContext(ctx, `SELECT t.kind, t.family_id, f.client_id FROM oauth_tokens t JOIN oauth_families f ON f.id = t.family_id WHERE t.token_hash = ?`, hash).Scan(&kind, &fid, &cid)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if cid != clientID {
			return nil
		}
		if kind == "refresh" {
			family = fid
			return revokeFamily(ctx, tx, fid, now)
		}
		_, err = tx.ExecContext(ctx, `UPDATE oauth_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL`, now, hash)
		return err
	})
	return family, err
}

// Authorization is a live family as the admin UI lists it.
type Authorization struct {
	Family
	ClientName string
}

// ListAuthorizations is an identity's live families, oldest first.
func (s *Store) ListAuthorizations(ctx context.Context, identityID string) ([]Authorization, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+familyCols+`, c.client_name FROM oauth_families f JOIN oauth_clients c ON c.client_id = f.client_id WHERE f.identity_id = ? AND f.revoked_at IS NULL ORDER BY f.created_at, f.id`, identityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Authorization{}
	for rows.Next() {
		var (
			a             Authorization
			created       int64
			used, revoked sql.NullInt64
		)
		if err := rows.Scan(&a.ID, &a.IdentityID, &a.ClientID, &a.RedirectURI, &a.Scope, &a.Resource, &created, &used, &revoked, &a.ClientName); err != nil {
			return nil, err
		}
		a.CreatedAt, a.LastUsedAt, a.RevokedAt = at(created), ms(used), ms(revoked)
		out = append(out, a)
	}
	return out, rows.Err()
}

// RevokeAuthorization revokes one of an identity's families and its tokens.
func (s *Store) RevokeAuthorization(ctx context.Context, identityID, familyID string) error {
	now := s.nowMS()
	return s.inTx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM oauth_families WHERE id = ? AND identity_id = ? AND revoked_at IS NULL`, familyID, identityID).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			return ErrNotFound
		}
		return revokeFamily(ctx, tx, familyID, now)
	})
}

// IdentityAuthorizationCounts is how many live families each identity has,
// for the consent page.
func (s *Store) IdentityAuthorizationCounts(ctx context.Context) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT identity_id, COUNT(*) FROM oauth_families WHERE revoked_at IS NULL GROUP BY identity_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var (
			id string
			n  int
		)
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

// CreateSession stores an admin session by the hash of its cookie.
func (s *Store) CreateSession(ctx context.Context, hash string, expires time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO admin_sessions (id_hash, created_at, expires_at) VALUES (?, ?, ?)`, hash, s.nowMS(), expires.UnixMilli())
	return err
}

// SessionValid reports whether a session exists and hasn't expired.
func (s *Store) SessionValid(ctx context.Context, hash string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM admin_sessions WHERE id_hash = ? AND expires_at > ?`, hash, s.nowMS()).Scan(&n)
	return n > 0, err
}

// DeleteSession ends an admin session.
func (s *Store) DeleteSession(ctx context.Context, hash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM admin_sessions WHERE id_hash = ?`, hash)
	return err
}

// CleanupOAuth deletes what has expired for good: pending requests, codes
// (a day after expiry, so a late replay still finds them), access tokens,
// used or expired refresh tokens of revoked families, and admin sessions.
func (s *Store) CleanupOAuth(ctx context.Context) error {
	now := s.nowMS()
	day := int64(24 * time.Hour / time.Millisecond)
	stmts := []struct {
		q    string
		args []any
	}{
		{`DELETE FROM oauth_requests WHERE expires_at <= ?`, []any{now}},
		{`DELETE FROM oauth_codes WHERE expires_at <= ?`, []any{now - day}},
		{`DELETE FROM oauth_tokens WHERE kind = 'access' AND expires_at <= ?`, []any{now - day}},
		{`DELETE FROM oauth_tokens WHERE kind = 'refresh' AND expires_at <= ?`, []any{now}},
		{`DELETE FROM oauth_families WHERE revoked_at IS NOT NULL AND revoked_at <= ?`, []any{now - 30*day}},
		{`DELETE FROM admin_sessions WHERE expires_at <= ?`, []any{now}},
	}
	for _, st := range stmts {
		if _, err := s.db.ExecContext(ctx, st.q, st.args...); err != nil {
			return err
		}
	}
	return nil
}
