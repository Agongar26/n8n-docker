CREATE TABLE sqli_incidents (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source_ip VARCHAR(50),
    username_attempt VARCHAR(100),
    malicious_payload TEXT
);