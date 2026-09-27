CREATE TABLE sso_users (
  id BINARY(16) PRIMARY KEY,
  subject CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE,
  display_name VARCHAR(120) NOT NULL,
  email VARCHAR(320) NULL,
  disabled_at TIMESTAMP(3) NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  UNIQUE KEY uq_sso_user_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE sso_identities (
  id BINARY(16) PRIMARY KEY,
  user_id BINARY(16) NOT NULL,
  provider VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  provider_subject VARCHAR(191) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  UNIQUE KEY uq_sso_identity_provider_subject (provider,provider_subject),
  KEY ix_sso_identity_user (user_id),
  CONSTRAINT fk_sso_identity_user FOREIGN KEY (user_id) REFERENCES sso_users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE sso_user_roles (
  user_id BINARY(16) NOT NULL,
  role_key VARCHAR(48) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  source VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (user_id,role_key,source),
  CONSTRAINT fk_sso_role_user FOREIGN KEY (user_id) REFERENCES sso_users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE discord_role_syncs (
  discord_user_id VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
  discord_guild_id VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  staff_roles JSON NOT NULL,
  updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  KEY ix_discord_role_sync_guild (discord_guild_id,updated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
