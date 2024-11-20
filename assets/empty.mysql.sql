START TRANSACTION;
CREATE TABLE `oauth_tokens` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `app` varchar(32) CHARACTER SET latin1 COLLATE latin1_swedish_ci NOT NULL,
  `type` varchar(16) NOT NULL,
  `client_id` varchar(64) CHARACTER SET latin1 COLLATE latin1_swedish_ci NOT NULL,
  `client_secret` varchar(256) CHARACTER SET latin1 COLLATE latin1_swedish_ci NOT NULL,
  `original_refresh_token` varchar(2048) CHARACTER SET latin1 COLLATE latin1_swedish_ci NOT NULL,
  `refresh_token` varchar(2048) CHARACTER SET latin1 COLLATE latin1_swedish_ci NOT NULL,
  `access_token` varchar(4096) CHARACTER SET latin1 COLLATE latin1_swedish_ci NOT NULL,
  `expires_at` datetime(6) DEFAULT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `code_exchange_response_body` text DEFAULT NULL,
  `code_verifier` varchar(128) NOT NULL DEFAULT '',
  `refresh_token_expires_at` datetime(6) DEFAULT NULL,
  PRIMARY KEY (`id`),
  INDEX `ot_app_client_id_client_secret` (`app`,`client_id`,`client_secret`) USING BTREE,
  UNIQUE KEY `ot_app_client_id_client_secret_refresh_token` (`app`,`client_id`,`client_secret`,`refresh_token`) USING BTREE,
  UNIQUE KEY `ot_app_original_refresh_token` (`app`,`original_refresh_token`) USING BTREE,
  UNIQUE KEY `ot_app_refresh_token` (`app`,`refresh_token`) USING BTREE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
CREATE TABLE `token_requests` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `app` varchar(32) CHARACTER SET latin1 COLLATE latin1_swedish_ci NOT NULL,
  `request_client_id` varchar(64) CHARACTER SET latin1 COLLATE latin1_swedish_ci NOT NULL,
  `request_client_secret` varchar(128) CHARACTER SET latin1 COLLATE latin1_swedish_ci NOT NULL,
  `request_refresh_token` varchar(2048) CHARACTER SET latin1 COLLATE latin1_swedish_ci NOT NULL,
  `request_code` varchar(128) NOT NULL,
  `request_redirect_url` varchar(128) NOT NULL,
  `request_code_verifier` varchar(128) NOT NULL,
  `response_access_token` varchar(4096) CHARACTER SET latin1 COLLATE latin1_swedish_ci NOT NULL,
  `response_token_type` varchar(16) CHARACTER SET latin1 COLLATE latin1_swedish_ci NOT NULL,
  `response_refresh_token` varchar(2048) CHARACTER SET latin1 COLLATE latin1_swedish_ci NOT NULL,
  `response_expiry` datetime(6) DEFAULT NULL,
  `response_extra` text NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
COMMIT;
