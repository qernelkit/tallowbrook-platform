-- Driver training records: hazmat, forklift and defensive-driving courses.
-- Dispatch checks these before assigning a hazmat load.

CREATE TABLE driver_training_certificates (
    record_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    driver_id integer NOT NULL,
    certificate_number text NOT NULL UNIQUE,
    course_code text NOT NULL,
    issuing_body text NOT NULL,
    issued_on date NOT NULL,
    expires_on date,
    document_key text,
    CHECK (expires_on IS NULL OR expires_on > issued_on)
);

CREATE INDEX dtc_driver_expiry_idx ON driver_training_certificates (driver_id, expires_on);
