CREATE TABLE users (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email            text NOT NULL,
  password_hash    text NOT NULL,
  token_version    integer NOT NULL DEFAULT 0,
  failed_attempts  integer NOT NULL DEFAULT 0,
  locked_until     timestamptz,
  totp_secret_enc  text,
  totp_enabled     boolean NOT NULL DEFAULT false,
  last_totp_step   bigint,
  created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_email_lower_idx ON users (lower(email));

CREATE TABLE backup_codes (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash  text NOT NULL,
  used_at    timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX backup_codes_user_idx ON backup_codes (user_id);

CREATE TABLE refresh_tokens (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  family_id   uuid NOT NULL,
  token_hash  text NOT NULL UNIQUE,
  expires_at  timestamptz NOT NULL,
  revoked_at  timestamptz,
  replaced_by uuid,
  user_agent  text,
  ip          text,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (family_id);
CREATE INDEX refresh_tokens_user_idx ON refresh_tokens (user_id);

CREATE TABLE whitelist_addresses (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id             uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  network             text NOT NULL,
  address             text NOT NULL,
  label               text,
  confirm_token_hash  text,
  confirmed_at        timestamptz,
  active_at           timestamptz NOT NULL,
  revoked_at          timestamptz,
  created_at          timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX whitelist_unique_live_idx ON whitelist_addresses (user_id, network, address) WHERE revoked_at IS NULL;
CREATE INDEX whitelist_confirm_idx ON whitelist_addresses (confirm_token_hash) WHERE confirm_token_hash IS NOT NULL;

CREATE TABLE audit_log (
  id         bigserial PRIMARY KEY,
  user_id    uuid,
  event      text NOT NULL,
  ip         text,
  user_agent text,
  metadata   jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_log_user_idx ON audit_log (user_id, created_at DESC);

CREATE FUNCTION forbid_audit_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_immutable BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION forbid_audit_mutation();
