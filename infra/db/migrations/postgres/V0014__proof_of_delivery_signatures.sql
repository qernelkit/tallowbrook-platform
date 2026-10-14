-- Proof of delivery: the recipient's handwritten signature captured on the
-- driver app, stored as an image in S3. Partitioned by depot so the nightly
-- archive job can work one partition at a time.

CREATE TABLE pod_signatures (
    pod_id bigint GENERATED ALWAYS AS IDENTITY,
    depot_id integer NOT NULL,
    shipment_id bigint NOT NULL,
    stop_sequence smallint NOT NULL,
    recipient_name text NOT NULL,
    signature_image_key text NOT NULL,
    signature_captured_at timestamptz NOT NULL,
    captured_lat numeric(9, 6),
    captured_lon numeric(9, 6),
    driver_id integer NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (depot_id, pod_id)
) PARTITION BY HASH (depot_id);

CREATE TABLE pod_signatures_p0 PARTITION OF pod_signatures FOR VALUES WITH (MODULUS 4, REMAINDER 0);
CREATE TABLE pod_signatures_p1 PARTITION OF pod_signatures FOR VALUES WITH (MODULUS 4, REMAINDER 1);
CREATE TABLE pod_signatures_p2 PARTITION OF pod_signatures FOR VALUES WITH (MODULUS 4, REMAINDER 2);
CREATE TABLE pod_signatures_p3 PARTITION OF pod_signatures FOR VALUES WITH (MODULUS 4, REMAINDER 3);

CREATE INDEX pod_signatures_shipment_idx ON pod_signatures (shipment_id);
CREATE UNIQUE INDEX pod_signatures_stop_idx ON pod_signatures (depot_id, shipment_id, stop_sequence);

COMMENT ON COLUMN pod_signatures.signature_image_key IS
    'S3 object key in tb-pod-images-<env>; the image itself never enters the database.';
