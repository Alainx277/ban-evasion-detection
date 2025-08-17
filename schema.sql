CREATE TABLE users (
    user_id SERIAL PRIMARY KEY,
    banned BOOLEAN NOT NULL DEFAULT false,
    trust INT NOT NULL DEFAULT 100,
    suspicious BOOLEAN NOT NULL DEFAULT false
);

CREATE TABLE fingerprint_kind (
    kind TEXT PRIMARY KEY,
    -- How confident are we in the users identity with this kind of fingerprint?
    confidence INT NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    -- How is the trustworthiness of the client increased if this identifier is present?
    present_trust INT NOT NULL DEFAULT 0,
    -- How is the trustworthiness of the client reduced if this identifier is absent?
    missing_trust INT NOT NULL DEFAULT 0
);

INSERT INTO fingerprint_kind (kind, confidence, present_trust, missing_trust)
VALUES
    ('RegistryKey',    100,   0,   0),
    ('MonitorId',       60,   0,  50),
    -- If TPM should be enforced missing_trust can be set to a high value
    ('TPM',            100, 100,   0),
    ('NetworkDevice',   10,   0,  50),
    ('IP',              20,   0,   0),
    ('Disk',            90,   0,  50),
    ('Volume',          90,   0,  50),
    ('CPU',              0,   0,   0),
    ('BIOS',            90,   0,  50)
ON CONFLICT (kind) DO NOTHING;

CREATE TABLE fingerprints (
    fingerprint_id SERIAL PRIMARY KEY,
    kind TEXT NOT NULL,
    data BYTEA NOT NULL,
    banned BOOLEAN NOT NULL DEFAULT false,
    UNIQUE (kind, data),
    FOREIGN KEY (kind) REFERENCES fingerprint_kind(kind)
);

CREATE TABLE user_fingerprints (
    user_id INT NOT NULL,
    fingerprint_id INT NOT NULL,
    PRIMARY KEY (user_id, fingerprint_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (fingerprint_id) REFERENCES fingerprints(fingerprint_id)
);

CREATE OR REPLACE FUNCTION ban_user(p_user_id INT)
RETURNS VOID AS $$
BEGIN
    -- Set the user account to banned
    UPDATE users
    SET banned = TRUE
    WHERE user_id = p_user_id;

    -- Ban all fingerprints associated with the user
    UPDATE fingerprints f
    SET banned = TRUE
    FROM user_fingerprints uf, fingerprint_kind fk
    WHERE uf.user_id = p_user_id
      AND uf.fingerprint_id = f.fingerprint_id
      AND f.kind = fk.kind
      AND fk.confidence >= 0;

END;
$$ LANGUAGE plpgsql;
