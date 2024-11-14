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
