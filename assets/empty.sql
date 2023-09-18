BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "token_requests" (
	"id"	INTEGER NOT NULL,
	"app"	TEXT NOT NULL,
	"request_client_id"	TEXT NOT NULL,
	"request_client_secret"	TEXT NOT NULL,
	"request_refresh_token"	TEXT NOT NULL,
	"request_code"	TEXT NOT NULL,
	"request_redirect_url"	TEXT NOT NULL,
	"request_code_verifier"	TEXT NOT NULL,
	"response_access_token"	TEXT NOT NULL,
	"response_token_type"	TEXT NOT NULL,
	"response_refresh_token"	TEXT NOT NULL,
	"response_expiry"	DATETIME NOT NULL,
	"response_extra"	TEXT NOT NULL,
	"created_at"	DATETIME NOT NULL,
	"updated_at"	DATETIME NOT NULL,
	PRIMARY KEY("id" AUTOINCREMENT)
);
CREATE TABLE IF NOT EXISTS "oauth_tokens" (
	"id"	INTEGER NOT NULL,
	"app"	TEXT NOT NULL,
	"type"	TEXT NOT NULL,
	"client_id"	TEXT NOT NULL,
	"client_secret"	TEXT NOT NULL,
	"original_refresh_token"	TEXT NOT NULL,
	"refresh_token"	TEXT NOT NULL,
	"access_token"	TEXT NOT NULL,
	"expires_at"	datetime,
	"created_at"	DATETIME NOT NULL,
	"updated_at"	DATETIME NOT NULL,
	"code_exchange_response_body"	TEXT,
	"code_verifier"	TEXT NOT NULL DEFAULT '',
	PRIMARY KEY("id" AUTOINCREMENT)
);
CREATE UNIQUE INDEX IF NOT EXISTS "ot_app_client_id_client_secret_refresh_token" ON "oauth_tokens" (
	"app",
	"client_id",
	"client_secret",
	"refresh_token"
);
CREATE UNIQUE INDEX IF NOT EXISTS "ot_app_client_id_client_secret_original_refresh_token" ON "oauth_tokens" (
	"app",
	"client_id",
	"client_secret",
	"original_refresh_token"
);
COMMIT;
