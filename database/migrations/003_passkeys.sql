ALTER TABLE sso_login_tickets
  ADD COLUMN authentication_method VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin
    NOT NULL DEFAULT 'legacy_panel' AFTER user_id;

CREATE TABLE sso_passkeys (
  id BINARY(16) PRIMARY KEY,
  user_id BINARY(16) NOT NULL,
  webauthn_user_id VARBINARY(64) NOT NULL,
  credential_id VARCHAR(1024) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  public_key BLOB NOT NULL,
  counter BIGINT UNSIGNED NOT NULL DEFAULT 0,
  device_type ENUM('singleDevice','multiDevice') NULL,
  backed_up BOOLEAN NOT NULL DEFAULT FALSE,
  transports JSON NULL,
  device_name VARCHAR(100) NULL,
  source VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'sso',
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  last_used_at TIMESTAMP(3) NULL,
  UNIQUE KEY uq_sso_passkey_credential (credential_id),
  KEY ix_sso_passkey_user (user_id),
  CONSTRAINT fk_sso_passkey_user FOREIGN KEY (user_id) REFERENCES sso_users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE sso_auth_challenges (
  id BINARY(16) PRIMARY KEY,
  interaction_uid VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  user_id BINARY(16) NULL,
  challenge VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  expires_at DATETIME(3) NOT NULL,
  consumed_at DATETIME(3) NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  KEY ix_sso_auth_challenge_interaction (interaction_uid,expires_at),
  KEY ix_sso_auth_challenge_cleanup (expires_at,consumed_at),
  CONSTRAINT fk_sso_auth_challenge_user FOREIGN KEY (user_id) REFERENCES sso_users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
