CREATE TABLE sso_oidc_artifacts (
  model VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  artifact_id VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  payload JSON NOT NULL,
  grant_id VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NULL,
  user_code VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NULL,
  uid VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NULL,
  expires_at DATETIME(3) NULL,
  PRIMARY KEY (model,artifact_id),
  KEY ix_sso_oidc_grant (model,grant_id),
  KEY ix_sso_oidc_user_code (model,user_code),
  KEY ix_sso_oidc_uid (model,uid),
  KEY ix_sso_oidc_expiry (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE sso_login_tickets (
  token_hash BINARY(32) PRIMARY KEY,
  interaction_uid VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  user_id BINARY(16) NOT NULL,
  expires_at DATETIME(3) NOT NULL,
  consumed_at DATETIME(3) NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  KEY ix_sso_login_ticket_interaction (interaction_uid,expires_at),
  KEY ix_sso_login_ticket_expiry (expires_at),
  CONSTRAINT fk_sso_login_ticket_user FOREIGN KEY (user_id) REFERENCES sso_users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
