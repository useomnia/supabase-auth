package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/crypto"
	"github.com/supabase/auth/internal/models"
)

// AuditSessionTestSuite groups the checks that session-bearing events record a
// top-level session_id on their audit_log_entries payload. Coverage for this
// cross-cutting feature lives here (one suite) rather than being scattered
// across each handler's suite; add a case here when a new event starts
// capturing the session.
type AuditSessionTestSuite struct {
	suite.Suite
	API    *API
	Config *conf.GlobalConfiguration
}

func TestAuditSession(t *testing.T) {
	api, config, err := setupAPIForTest()
	require.NoError(t, err)

	ts := &AuditSessionTestSuite{
		API:    api,
		Config: config,
	}
	defer api.db.Close()

	suite.Run(t, ts)
}

func (ts *AuditSessionTestSuite) SetupTest() {
	models.TruncateAll(ts.API.db)
}

// newUserWithSession creates a confirmed user with a session and returns an
// access token bound to that session.
func (ts *AuditSessionTestSuite) newUserWithSession(email string) (*models.User, *models.Session, string) {
	u, err := models.NewUser("", email, "password", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err)
	now := time.Now()
	u.EmailConfirmedAt = &now
	require.NoError(ts.T(), ts.API.db.Create(u))

	session, err := models.NewSession(u.ID, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(session))

	req := httptest.NewRequest(http.MethodPost, "/token?grant_type=password", nil)
	token, _, err := ts.API.generateAccessToken(req, ts.API.db, u, &session.ID, models.PasswordGrant)
	require.NoError(ts.T(), err)

	return u, session, token
}

// do issues an authenticated JSON request against the API handler.
func (ts *AuditSessionTestSuite) do(method, path, token string, body interface{}) *httptest.ResponseRecorder {
	var buffer bytes.Buffer
	if body != nil {
		require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(body))
	}
	req := httptest.NewRequest(method, path, &buffer)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	return w
}

// requireAuditSessionID asserts that an audit log entry for action exists and
// records session_id equal to want. This is the single-line check each case
// below relies on.
func (ts *AuditSessionTestSuite) requireAuditSessionID(action models.AuditAction, want uuid.UUID) {
	entries, err := models.FindAuditLogEntries(ts.API.db, []string{}, "", nil)
	require.NoError(ts.T(), err)
	for _, entry := range entries {
		if entry.Payload["action"] == string(action) {
			require.Contains(ts.T(), entry.Payload, "session_id", "%s entry should carry session_id", action)
			require.Equal(ts.T(), want.String(), entry.Payload["session_id"], "%s session_id mismatch", action)
			return
		}
	}
	require.FailNowf(ts.T(), "audit entry not found", "no %s audit log entry was written", action)
}

func (ts *AuditSessionTestSuite) TestLogout() {
	_, session, token := ts.newUserWithSession("logout@example.com")

	w := ts.do(http.MethodPost, "http://localhost/logout", token, nil)
	require.Equal(ts.T(), http.StatusNoContent, w.Code)

	ts.requireAuditSessionID(models.LogoutAction, session.ID)
}

func (ts *AuditSessionTestSuite) TestUserModified() {
	_, session, token := ts.newUserWithSession("modify@example.com")

	w := ts.do(http.MethodPut, "http://localhost/user", token, map[string]interface{}{
		"data": map[string]interface{}{"favorite_color": "blue"},
	})
	require.Equal(ts.T(), http.StatusOK, w.Code)

	ts.requireAuditSessionID(models.UserModifiedAction, session.ID)
}

func (ts *AuditSessionTestSuite) TestPasswordUpdated() {
	_, session, token := ts.newUserWithSession("password@example.com")

	w := ts.do(http.MethodPut, "http://localhost/user", token, map[string]interface{}{
		"password": "newsecurepassword",
	})
	require.Equal(ts.T(), http.StatusOK, w.Code)

	ts.requireAuditSessionID(models.UserUpdatePasswordAction, session.ID)
}

func (ts *AuditSessionTestSuite) TestMFAEnroll() {
	_, session, token := ts.newUserWithSession("mfa@example.com")

	w := ts.do(http.MethodPost, "http://localhost/factors", token, EnrollFactorParams{
		FriendlyName: "test-totp",
		FactorType:   models.TOTP,
		Issuer:       "supabase.com",
	})
	require.Equal(ts.T(), http.StatusOK, w.Code)

	ts.requireAuditSessionID(models.EnrollFactorAction, session.ID)
}

// TestLoginPassword covers a login event, whose session is created during the
// request (inside token issuance) and recorded on the audit entry written
// afterwards. The created session's ID is read back from the response header.
func (ts *AuditSessionTestSuite) TestLoginPassword() {
	email := "login-pw@example.com"
	ts.newUserWithSession(email) // creates a confirmed user with password "password"

	w := ts.do(http.MethodPost, "http://localhost/token?grant_type=password", "", map[string]interface{}{
		"email":    email,
		"password": "password",
	})
	require.Equal(ts.T(), http.StatusOK, w.Code)

	sessionID, err := uuid.FromString(w.Header().Get("sb-auth-session-id"))
	require.NoError(ts.T(), err, "expected a sb-auth-session-id response header")

	ts.requireAuditSessionID(models.LoginAction, sessionID)
}

// TestSignupVerify covers user_signedup emitted when a signup is confirmed via
// /verify and a session is issued in the same request (the deferred-audit path).
func (ts *AuditSessionTestSuite) TestSignupVerify() {
	email := "signup-verify@example.com"
	const rawToken = "778899"
	u, err := models.NewUser("", email, "password", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err)
	now := time.Now()
	u.ConfirmationToken = crypto.GenerateTokenHash(email, rawToken)
	u.ConfirmationSentAt = &now
	require.NoError(ts.T(), ts.API.db.Create(u))
	i, err := models.NewIdentity(u, "email", map[string]interface{}{
		"sub": u.ID.String(), "email": email, "email_verified": false,
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(i))
	require.NoError(ts.T(), models.CreateOneTimeToken(ts.API.db, u.ID, u.GetEmail(), u.ConfirmationToken, models.ConfirmationToken))

	w := ts.do(http.MethodPost, "http://localhost/verify", "", map[string]interface{}{
		"type":  "signup",
		"token": rawToken,
		"email": email,
	})
	require.Equal(ts.T(), http.StatusOK, w.Code)

	sessionID, err := uuid.FromString(w.Header().Get("sb-auth-session-id"))
	require.NoError(ts.T(), err, "expected a sb-auth-session-id response header")
	ts.requireAuditSessionID(models.UserSignedUpAction, sessionID)
}

// TestRecoveryLogin covers login emitted when an already-confirmed user verifies
// a recovery/magic-link token via /verify and a session is issued.
func (ts *AuditSessionTestSuite) TestRecoveryLogin() {
	email := "recovery-login@example.com"
	const rawToken = "112233"
	u, err := models.NewUser("", email, "password", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err)
	now := time.Now()
	u.EmailConfirmedAt = &now
	u.RecoveryToken = crypto.GenerateTokenHash(email, rawToken)
	u.RecoverySentAt = &now
	require.NoError(ts.T(), ts.API.db.Create(u))
	require.NoError(ts.T(), models.CreateOneTimeToken(ts.API.db, u.ID, u.GetEmail(), u.RecoveryToken, models.RecoveryToken))

	w := ts.do(http.MethodPost, "http://localhost/verify", "", map[string]interface{}{
		"type":  "recovery",
		"token": rawToken,
		"email": email,
	})
	require.Equal(ts.T(), http.StatusOK, w.Code)

	sessionID, err := uuid.FromString(w.Header().Get("sb-auth-session-id"))
	require.NoError(ts.T(), err, "expected a sb-auth-session-id response header")
	ts.requireAuditSessionID(models.LoginAction, sessionID)
}

// TestExternalSignupDeferredAudit verifies that the shared social/SSO account
// helper reports a user_signedup audit intent for a new, email-verified
// external account. The caller then writes it with the issued session_id (the
// writeDeferredAudit path exercised end-to-end by the /verify tests above).
func (ts *AuditSessionTestSuite) TestExternalSignupDeferredAudit() {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/callback", nil)
	userData := &provider.UserProvidedData{
		Metadata: &provider.Claims{Subject: "external-subject-1"},
		Emails:   []provider.Email{{Email: "ext-signup@example.com", Verified: true, Primary: true}},
	}

	decision, user, pending, err := ts.API.createAccountFromExternalIdentity(ts.API.db, req, userData, "google", false)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), models.CreateAccount, decision)
	require.NotNil(ts.T(), user)
	require.NotNil(ts.T(), pending, "expected a deferred audit intent")
	require.Equal(ts.T(), models.UserSignedUpAction, pending.action)
	require.Equal(ts.T(), "google", pending.traits["provider"])
}

// TestTokenRefreshAndRevoke covers the two events that don't source the session
// from the request context: token_refreshed (from the local session) and
// token_revoked (from the swapped refresh token's SessionId).
func (ts *AuditSessionTestSuite) TestTokenRefreshAndRevoke() {
	u, err := models.NewUser("", "refresh@example.com", "password", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err)
	now := time.Now()
	u.EmailConfirmedAt = &now
	require.NoError(ts.T(), ts.API.db.Create(u))

	rt, err := models.GrantAuthenticatedUser(ts.API.db, u, models.GrantParams{})
	require.NoError(ts.T(), err)
	require.NotNil(ts.T(), rt.SessionId)

	w := ts.do(http.MethodPost, "http://localhost/token?grant_type=refresh_token", "", map[string]interface{}{
		"refresh_token": rt.Token,
	})
	require.Equal(ts.T(), http.StatusOK, w.Code)

	ts.requireAuditSessionID(models.TokenRefreshedAction, *rt.SessionId)
	ts.requireAuditSessionID(models.TokenRevokedAction, *rt.SessionId)
}
