-- Local-only Temporal databases and credentials. Never reuse outside this profile.
CREATE ROLE temporal LOGIN PASSWORD 'temporal-local-only';
CREATE DATABASE temporal OWNER temporal;
CREATE DATABASE temporal_visibility OWNER temporal;
