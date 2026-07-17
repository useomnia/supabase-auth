package models

import (
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
)

func TestWithSession(t *testing.T) {
	sessionID := uuid.Must(uuid.NewV4())
	session := &Session{ID: sessionID}

	t.Run("adds session_id when session is present", func(t *testing.T) {
		payload := map[string]interface{}{}
		WithSession(session)(payload)

		assert.Equal(t, sessionID, payload["session_id"])
	})

	t.Run("omits session_id when session is nil", func(t *testing.T) {
		payload := map[string]interface{}{}
		WithSession(nil)(payload)

		assert.NotContains(t, payload, "session_id")
	})
}

func TestWithSessionID(t *testing.T) {
	sessionID := uuid.Must(uuid.NewV4())

	t.Run("adds session_id when pointer is non-nil", func(t *testing.T) {
		payload := map[string]interface{}{}
		WithSessionID(&sessionID)(payload)

		assert.Equal(t, sessionID, payload["session_id"])
	})

	t.Run("omits session_id when pointer is nil", func(t *testing.T) {
		payload := map[string]interface{}{}
		WithSessionID(nil)(payload)

		assert.NotContains(t, payload, "session_id")
	})
}
