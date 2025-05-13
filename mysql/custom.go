package mysql

import (
	"context"
	"time"
)

func OauthTokensByAppAccessToken(ctx context.Context, db DB, app, accessToken string) ([]*OauthToken, error) {
	// query
	const sqlstr = `SELECT ` +
		`id, app, type, client_id, client_secret, original_refresh_token, refresh_token, access_token, expires_at, created_at, updated_at, code_exchange_response_body, code_verifier, refresh_token_expires_at ` +
		`FROM oauth_proxy.oauth_tokens ` +
		`WHERE app = ? AND access_token = ? AND (refresh_token_expires_at IS NULL OR refresh_token_expires_at > ?)`
	// run
	logf(sqlstr, app, accessToken)
	refreshTokenExpiresAt := time.Now()
	rows, err := db.QueryContext(ctx, sqlstr, app, accessToken, refreshTokenExpiresAt)
	if err != nil {
		return nil, logerror(err)
	}
	defer rows.Close()
	// process
	var res []*OauthToken
	for rows.Next() {
		ot := OauthToken{
			_exists: true,
		}
		// scan
		if err := rows.Scan(&ot.ID, &ot.App, &ot.Type, &ot.ClientID, &ot.ClientSecret, &ot.OriginalRefreshToken, &ot.RefreshToken, &ot.AccessToken, &ot.ExpiresAt, &ot.CreatedAt, &ot.UpdatedAt, &ot.CodeExchangeResponseBody, &ot.CodeVerifier, &ot.RefreshTokenExpiresAt); err != nil {
			return nil, logerror(err)
		}
		res = append(res, &ot)
	}
	if err := rows.Err(); err != nil {
		return nil, logerror(err)
	}
	return res, nil
}

func OauthTokenByAppClientIDClientSecretRefreshTokenOrOriginalRefreshToken(ctx context.Context, db DB, app, clientID, clientSecret, refreshToken string) (*OauthToken, error) {
	// query
	const sqlstr = `SELECT ` +
		`id, app, type, grant_type, client_id, client_secret, username, original_refresh_token, refresh_token, access_token, expires_at, created_at, updated_at, code_exchange_response_body, code_verifier, refresh_token_expires_at ` +
		`FROM oauth_proxy.oauth_tokens ` +
		`USE INDEX (ot_app_client_id_client_secret) ` +
		`WHERE app = ? AND client_id = ? AND client_secret = ? ` +
		`AND (refresh_token = ? OR original_refresh_token = ?)` +
		`ORDER BY updated_at DESC ` +
		`LIMIT 1 ` +
		`FOR UPDATE`
	// run
	logf(sqlstr, app, clientID, clientSecret, refreshToken, refreshToken)
	ot := OauthToken{
		_exists: true,
	}
	if err := db.QueryRowContext(ctx, sqlstr, app, clientID, clientSecret, refreshToken, refreshToken).Scan(&ot.ID, &ot.App, &ot.Type, &ot.GrantType, &ot.ClientID, &ot.ClientSecret, &ot.Username, &ot.OriginalRefreshToken, &ot.RefreshToken, &ot.AccessToken, &ot.ExpiresAt, &ot.CreatedAt, &ot.UpdatedAt, &ot.CodeExchangeResponseBody, &ot.CodeVerifier, &ot.RefreshTokenExpiresAt); err != nil {
		return nil, logerror(err)
	}
	return &ot, nil
}


func OauthTokenByAppClientIDClientSecretUsername(ctx context.Context, db DB, app, clientID, clientSecret, username string) (*OauthToken, error) {
	// query
	const sqlstr = `SELECT ` +
		`id, app, type, grant_type, client_id, client_secret, username, original_refresh_token, refresh_token, access_token, expires_at, created_at, updated_at, code_exchange_response_body, code_verifier, refresh_token_expires_at ` +
		`FROM oauth_proxy.oauth_tokens ` +
		`USE INDEX (ot_app_client_id_client_secret) ` +
		`WHERE app = ? AND client_id = ? AND client_secret = ? ` +
		`AND (username = ?)` +
		`ORDER BY updated_at DESC ` +
		`LIMIT 1 ` +
		`FOR UPDATE`
	// run
	logf(sqlstr, app, clientID, clientSecret, username)
	ot := OauthToken{
		_exists: true,
	}
	if err := db.QueryRowContext(ctx, sqlstr, app, clientID, clientSecret, username).Scan(&ot.ID, &ot.App, &ot.Type, &ot.GrantType, &ot.ClientID, &ot.ClientSecret, &ot.Username, &ot.OriginalRefreshToken, &ot.RefreshToken, &ot.AccessToken, &ot.ExpiresAt, &ot.CreatedAt, &ot.UpdatedAt, &ot.CodeExchangeResponseBody, &ot.CodeVerifier, &ot.RefreshTokenExpiresAt); err != nil {
		return nil, logerror(err)
	}
	return &ot, nil
}

func OauthTokenByAppClientIDClientSecret(ctx context.Context, db DB, app, clientID, clientSecret string) (*OauthToken, error) {
	// query
	const sqlstr = `SELECT ` +
		`id, app, type, grant_type, client_id, client_secret, username, original_refresh_token, refresh_token, access_token, expires_at, created_at, updated_at, code_exchange_response_body, code_verifier, refresh_token_expires_at ` +
		`FROM oauth_proxy.oauth_tokens ` +
		`USE INDEX (ot_app_client_id_client_secret) ` +
		`WHERE app = ? AND client_id = ? AND client_secret = ? ` +
		`ORDER BY updated_at DESC ` +
		`LIMIT 1 ` +
		`FOR UPDATE`
	// run
	logf(sqlstr, app, clientID, clientSecret)
	ot := OauthToken{
		_exists: true,
	}
	if err := db.QueryRowContext(ctx, sqlstr, app, clientID, clientSecret).Scan(&ot.ID, &ot.App, &ot.Type, &ot.GrantType, &ot.ClientID, &ot.ClientSecret, &ot.Username, &ot.OriginalRefreshToken, &ot.RefreshToken, &ot.AccessToken, &ot.ExpiresAt, &ot.CreatedAt, &ot.UpdatedAt, &ot.CodeExchangeResponseBody, &ot.CodeVerifier, &ot.RefreshTokenExpiresAt); err != nil {
		return nil, logerror(err)
	}
	return &ot, nil
}

