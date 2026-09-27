CREATE TABLE discord_link_tickets (
  id BINARY(16) PRIMARY KEY,
  discord_user_id VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  discord_guild_id VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  token_hash BINARY(32) NOT NULL,
  expires_at DATETIME(3) NOT NULL,
  consumed_at DATETIME(3) NULL,
  linked_user_id BINARY(16) NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  UNIQUE KEY uq_discord_link_ticket_token (token_hash),
  KEY ix_discord_link_ticket_user (discord_user_id,consumed_at,expires_at),
  KEY ix_discord_link_ticket_cleanup (expires_at,consumed_at),
  CONSTRAINT fk_discord_link_ticket_user
    FOREIGN KEY (linked_user_id) REFERENCES sso_users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
