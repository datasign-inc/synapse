CREATE TABLE IF NOT EXISTS vp_session_management (
    sid TEXT PRIMARY KEY,
    vp_type NOT NULL, -- ageOver13 or affiliation or ...
    status TEXT NOT NULL,
    ro_nonce TEXT NOT NULL,
    created_ts BIGINT NOT NULL
);