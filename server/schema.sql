CREATE TABLE roles (id SERIAL PRIMARY KEY, name VARCHAR(40) UNIQUE NOT NULL);
CREATE TABLE users (id UUID PRIMARY KEY, role_id INT REFERENCES roles(id), full_name VARCHAR(120) NOT NULL, email VARCHAR(255) UNIQUE NOT NULL, password_hash TEXT NOT NULL, status VARCHAR(20) DEFAULT 'active', created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE security_events (id UUID PRIMARY KEY, event_type VARCHAR(80), source VARCHAR(255), severity VARCHAR(20), status VARCHAR(30), occurred_at TIMESTAMPTZ DEFAULT now(), metadata JSONB);
CREATE TABLE alerts (id UUID PRIMARY KEY, title VARCHAR(160), description TEXT, severity VARCHAR(20), source VARCHAR(120), status VARCHAR(30), assigned_user_id UUID REFERENCES users(id), created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE vulnerabilities (id UUID PRIMARY KEY, name VARCHAR(160), severity VARCHAR(20), component VARCHAR(160), description TEXT, remediation TEXT, status VARCHAR(30));
CREATE TABLE scan_results (id UUID PRIMARY KEY, user_id UUID REFERENCES users(id), target TEXT, score INT, risk_level VARCHAR(20), findings JSONB, created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE analysis_results (id UUID PRIMARY KEY, user_id UUID REFERENCES users(id), subject TEXT, result JSONB, created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE reports (id UUID PRIMARY KEY, user_id UUID REFERENCES users(id), target TEXT, content JSONB, created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE audit_logs (id BIGSERIAL PRIMARY KEY, user_id UUID REFERENCES users(id), action VARCHAR(120), resource VARCHAR(255), status VARCHAR(30), ip_address INET, created_at TIMESTAMPTZ DEFAULT now());
