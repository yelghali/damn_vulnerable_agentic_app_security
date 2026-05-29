-- Offline SQLite seed for local testing (mirrors the PostgreSQL schema).
-- Sample / synthetic data only. NEVER use real customer data in this lab.

CREATE TABLE customers (
    customer_id TEXT PRIMARY KEY,
    full_name   TEXT NOT NULL,
    email       TEXT NOT NULL,
    ssn         TEXT NOT NULL,
    address     TEXT
);

CREATE TABLE accounts (
    account_id   TEXT PRIMARY KEY,
    customer_id  TEXT NOT NULL REFERENCES customers(customer_id),
    account_type TEXT NOT NULL,
    balance      REAL NOT NULL,
    currency     TEXT NOT NULL DEFAULT 'USD'
);

CREATE TABLE transactions (
    txn_id      TEXT PRIMARY KEY,
    account_id  TEXT NOT NULL REFERENCES accounts(account_id),
    amount      REAL NOT NULL,
    description TEXT,
    posted_at   TEXT NOT NULL
);

CREATE TABLE credit_scores (
    customer_id TEXT PRIMARY KEY REFERENCES customers(customer_id),
    score       INTEGER NOT NULL,
    bureau      TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

INSERT INTO customers VALUES
('CUST-1001', 'Alex Rivera',  'alex.rivera@example.com',  '111-22-3333', '12 Maple St, Seattle WA'),
('CUST-1002', 'Priya Singh',  'priya.singh@example.com',  '444-55-6666', '88 Oak Ave, Austin TX');

INSERT INTO accounts VALUES
('ACC-100001', 'CUST-1001', 'checking', 4200.55, 'USD'),
('ACC-100002', 'CUST-1001', 'savings',  18250.00, 'USD'),
('ACC-200001', 'CUST-1002', 'checking', 950.10,  'USD'),
('ACC-200002', 'CUST-1002', 'savings',  53200.75, 'USD');

INSERT INTO transactions VALUES
('TXN-1', 'ACC-100001', -54.20,  'Grocery store',   '2026-05-01'),
('TXN-2', 'ACC-100001', -120.00, 'Electricity bill','2026-05-03'),
('TXN-3', 'ACC-100001',  2500.00,'Payroll',         '2026-05-05'),
('TXN-4', 'ACC-200001', -33.10,  'Coffee shop',     '2026-05-02'),
('TXN-5', 'ACC-200001',  1800.00,'Payroll',         '2026-05-05');

INSERT INTO credit_scores VALUES
('CUST-1001', 742, 'Equifax',   '2026-04-30'),
('CUST-1002', 688, 'TransUnion','2026-04-30');
