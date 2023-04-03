// Package db contains the types for schema ''.
package db

// Code generated by xo. DO NOT EDIT.

import (
	"database/sql"
	"errors"
	"time"
)

// OauthToken represents a row from 'oauth_tokens'.
type OauthToken struct {
	ID                       int            `json:"id"`                          // id
	App                      string         `json:"app"`                         // app
	Type                     string         `json:"type"`                        // type
	ClientID                 string         `json:"client_id"`                   // client_id
	ClientSecret             string         `json:"client_secret"`               // client_secret
	OriginalRefreshToken     string         `json:"original_refresh_token"`      // original_refresh_token
	RefreshToken             string         `json:"refresh_token"`               // refresh_token
	AccessToken              string         `json:"access_token"`                // access_token
	ExpiresAt                time.Time  `json:"expires_at"`                  // expires_at
	CreatedAt                time.Time  `json:"created_at"`                  // created_at
	UpdatedAt                time.Time  `json:"updated_at"`                  // updated_at
	CodeExchangeResponseBody sql.NullString `json:"code_exchange_response_body"` // code_exchange_response_body

	// xo fields
	_exists, _deleted bool
}

// Exists determines if the OauthToken exists in the database.
func (ot *OauthToken) Exists() bool {
	return ot._exists
}

// Deleted provides information if the OauthToken has been deleted from the database.
func (ot *OauthToken) Deleted() bool {
	return ot._deleted
}

// Insert inserts the OauthToken to the database.
func (ot *OauthToken) Insert(db XODB) error {
	var err error

	// if already exist, bail
	if ot._exists {
		return errors.New("insert failed: already exists")
	}

	// sql insert query, primary key provided by autoincrement
	const sqlstr = `INSERT INTO oauth_tokens (` +
		`app, type, client_id, client_secret, original_refresh_token, refresh_token, access_token, expires_at, created_at, updated_at, code_exchange_response_body` +
		`) VALUES (` +
		`?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?` +
		`)`

	// run query
	XOLog(sqlstr, ot.App, ot.Type, ot.ClientID, ot.ClientSecret, ot.OriginalRefreshToken, ot.RefreshToken, ot.AccessToken, ot.ExpiresAt, ot.CreatedAt, ot.UpdatedAt, ot.CodeExchangeResponseBody)
	res, err := db.Exec(sqlstr, ot.App, ot.Type, ot.ClientID, ot.ClientSecret, ot.OriginalRefreshToken, ot.RefreshToken, ot.AccessToken, ot.ExpiresAt, ot.CreatedAt, ot.UpdatedAt, ot.CodeExchangeResponseBody)
	if err != nil {
		return err
	}

	// retrieve id
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}

	// set primary key and existence
	ot.ID = int(id)
	ot._exists = true

	return nil
}

// Update updates the OauthToken in the database.
func (ot *OauthToken) Update(db XODB) error {
	var err error

	// if doesn't exist, bail
	if !ot._exists {
		return errors.New("update failed: does not exist")
	}

	// if deleted, bail
	if ot._deleted {
		return errors.New("update failed: marked for deletion")
	}

	// sql query
	const sqlstr = `UPDATE oauth_tokens SET ` +
		`app = ?, type = ?, client_id = ?, client_secret = ?, original_refresh_token = ?, refresh_token = ?, access_token = ?, expires_at = ?, created_at = ?, updated_at = ?, code_exchange_response_body = ?` +
		` WHERE id = ?`

	// run query
	XOLog(sqlstr, ot.App, ot.Type, ot.ClientID, ot.ClientSecret, ot.OriginalRefreshToken, ot.RefreshToken, ot.AccessToken, ot.ExpiresAt, ot.CreatedAt, ot.UpdatedAt, ot.CodeExchangeResponseBody, ot.ID)
	_, err = db.Exec(sqlstr, ot.App, ot.Type, ot.ClientID, ot.ClientSecret, ot.OriginalRefreshToken, ot.RefreshToken, ot.AccessToken, ot.ExpiresAt, ot.CreatedAt, ot.UpdatedAt, ot.CodeExchangeResponseBody, ot.ID)
	return err
}

// Save saves the OauthToken to the database.
func (ot *OauthToken) Save(db XODB) error {
	if ot.Exists() {
		return ot.Update(db)
	}

	return ot.Insert(db)
}

// Delete deletes the OauthToken from the database.
func (ot *OauthToken) Delete(db XODB) error {
	var err error

	// if doesn't exist, bail
	if !ot._exists {
		return nil
	}

	// if deleted, bail
	if ot._deleted {
		return nil
	}

	// sql query
	const sqlstr = `DELETE FROM oauth_tokens WHERE id = ?`

	// run query
	XOLog(sqlstr, ot.ID)
	_, err = db.Exec(sqlstr, ot.ID)
	if err != nil {
		return err
	}

	// set deleted
	ot._deleted = true

	return nil
}

// OauthTokenByID retrieves a row from 'oauth_tokens' as a OauthToken.
//
// Generated from index 'oauth_tokens_id_pkey'.
func OauthTokenByID(db XODB, id int) (*OauthToken, error) {
	var err error

	// sql query
	const sqlstr = `SELECT ` +
		`id, app, type, client_id, client_secret, original_refresh_token, refresh_token, access_token, expires_at, created_at, updated_at, code_exchange_response_body ` +
		`FROM oauth_tokens ` +
		`WHERE id = ?`

	// run query
	XOLog(sqlstr, id)
	ot := OauthToken{
		_exists: true,
	}

	err = db.QueryRow(sqlstr, id).Scan(&ot.ID, &ot.App, &ot.Type, &ot.ClientID, &ot.ClientSecret, &ot.OriginalRefreshToken, &ot.RefreshToken, &ot.AccessToken, &ot.ExpiresAt, &ot.CreatedAt, &ot.UpdatedAt, &ot.CodeExchangeResponseBody)
	if err != nil {
		return nil, err
	}

	return &ot, nil
}

// OauthTokenByAppClientIDClientSecretOriginalRefreshToken retrieves a row from 'oauth_tokens' as a OauthToken.
//
// Generated from index 'ot_app_client_id_client_secret_original_refresh_token'.
func OauthTokenByAppClientIDClientSecretOriginalRefreshToken(db XODB, app string, clientID string, clientSecret string, originalRefreshToken string) (*OauthToken, error) {
	var err error

	// sql query
	const sqlstr = `SELECT ` +
		`id, app, type, client_id, client_secret, original_refresh_token, refresh_token, access_token, expires_at, created_at, updated_at, code_exchange_response_body ` +
		`FROM oauth_tokens ` +
		`WHERE app = ? AND client_id = ? AND client_secret = ? AND original_refresh_token = ?`

	// run query
	XOLog(sqlstr, app, clientID, clientSecret, originalRefreshToken)
	ot := OauthToken{
		_exists: true,
	}

	err = db.QueryRow(sqlstr, app, clientID, clientSecret, originalRefreshToken).Scan(&ot.ID, &ot.App, &ot.Type, &ot.ClientID, &ot.ClientSecret, &ot.OriginalRefreshToken, &ot.RefreshToken, &ot.AccessToken, &ot.ExpiresAt, &ot.CreatedAt, &ot.UpdatedAt, &ot.CodeExchangeResponseBody)
	if err != nil {
		return nil, err
	}

	return &ot, nil
}

// OauthTokenByAppClientIDClientSecretRefreshToken retrieves a row from 'oauth_tokens' as a OauthToken.
//
// Generated from index 'ot_app_client_id_client_secret_refresh_token'.
func OauthTokenByAppClientIDClientSecretRefreshToken(db XODB, app string, clientID string, clientSecret string, refreshToken string) (*OauthToken, error) {
	var err error

	// sql query
	const sqlstr = `SELECT ` +
		`id, app, type, client_id, client_secret, original_refresh_token, refresh_token, access_token, expires_at, created_at, updated_at, code_exchange_response_body ` +
		`FROM oauth_tokens ` +
		`WHERE app = ? AND client_id = ? AND client_secret = ? AND refresh_token = ?`

	// run query
	XOLog(sqlstr, app, clientID, clientSecret, refreshToken)
	ot := OauthToken{
		_exists: true,
	}

	err = db.QueryRow(sqlstr, app, clientID, clientSecret, refreshToken).Scan(&ot.ID, &ot.App, &ot.Type, &ot.ClientID, &ot.ClientSecret, &ot.OriginalRefreshToken, &ot.RefreshToken, &ot.AccessToken, &ot.ExpiresAt, &ot.CreatedAt, &ot.UpdatedAt, &ot.CodeExchangeResponseBody)
	if err != nil {
		return nil, err
	}

	return &ot, nil
}
