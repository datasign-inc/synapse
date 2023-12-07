CREATE TABLE IF NOT EXISTS user_vp_data (
    user_id TEXT NOT NULL,
    vp_type TEXT NOT NULL,
    verified_claims TEXT NOT NULL,
    raw_vp_token TEXT NOT NULL,
    created_ts BIGINT NOT NULL
);