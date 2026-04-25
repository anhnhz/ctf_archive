CREATE TABLE workspaces (
    id SERIAL PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    owner_token VARCHAR(256) NOT NULL,
    account_id VARCHAR(64) NOT NULL DEFAULT '',
    pipeline_state VARCHAR(32) DEFAULT 'DRAFT',
    manifest_hash VARCHAR(256),
    webhook_url VARCHAR(512),
    created_at TIMESTAMP DEFAULT now()
);

CREATE TABLE pipeline_transitions (
    id SERIAL PRIMARY KEY,
    workspace_id INT REFERENCES workspaces(id) ON DELETE CASCADE,
    from_state VARCHAR(32) NOT NULL,
    to_state VARCHAR(32) NOT NULL,
    params JSONB,
    created_at TIMESTAMP DEFAULT now()
);

CREATE TABLE deploy_tokens (
    id SERIAL PRIMARY KEY,
    workspace_id INT REFERENCES workspaces(id) ON DELETE CASCADE,
    token VARCHAR(256) UNIQUE NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT now()
);

CREATE OR REPLACE FUNCTION check_pipeline_transition()
RETURNS TRIGGER AS $$
DECLARE
    _algo TEXT;
    _nonce TEXT;
BEGIN
    IF OLD.pipeline_state = NEW.pipeline_state THEN
        RETURN NEW;
    END IF;

    IF OLD.pipeline_state = 'QUARANTINED' AND NEW.pipeline_state = 'DRAFT' THEN
        RETURN NEW;
    END IF;

    IF OLD.pipeline_state = 'DRAFT' AND NEW.pipeline_state = 'BUILD' THEN
        IF OLD.manifest_hash IS NOT NULL THEN
            RETURN NEW;
        END IF;
        NEW.pipeline_state := 'QUARANTINED';
        RETURN NEW;
    END IF;

    IF OLD.pipeline_state = 'BUILD' AND NEW.pipeline_state = 'SIGNED' THEN
        SELECT params->>'digest_algorithm', params->>'signing_nonce'
        INTO _algo, _nonce
        FROM pipeline_transitions
        WHERE workspace_id = NEW.id
          AND to_state = 'SIGNED'
        ORDER BY created_at DESC
        LIMIT 1;

        IF _algo = 'blake3' AND _nonce IS NOT NULL AND _nonce = OLD.manifest_hash THEN
            RETURN NEW;
        END IF;
        NEW.pipeline_state := 'QUARANTINED';
        RETURN NEW;
    END IF;

    IF OLD.pipeline_state = 'SIGNED' AND NEW.pipeline_state = 'REVIEW' THEN
        IF OLD.webhook_url IS NOT NULL THEN
            RETURN NEW;
        END IF;
        NEW.pipeline_state := 'QUARANTINED';
        RETURN NEW;
    END IF;

    NEW.pipeline_state := 'QUARANTINED';
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_pipeline_state
    BEFORE UPDATE ON workspaces
    FOR EACH ROW
    WHEN (OLD.pipeline_state IS DISTINCT FROM NEW.pipeline_state)
    EXECUTE FUNCTION check_pipeline_transition();

INSERT INTO workspaces (name, owner_token, account_id, pipeline_state)
VALUES ('harbor-default', 'tok_user_stack_fake', 'system', 'DRAFT');

CREATE TABLE phase1_seed_policies (
    kid VARCHAR(128) PRIMARY KEY,
    pem TEXT NOT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'user',
    created_at TIMESTAMP DEFAULT now()
);
