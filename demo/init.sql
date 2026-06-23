CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    ssn TEXT NOT NULL,        -- exists to make DELETE feel dangerous
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id),
    amount DECIMAL(10,2),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO users (name, email, ssn) VALUES
    ('Alice Johnson', 'alice@acme.com', '123-45-6789'),
    ('Bob Smith', 'bob@acme.com', '234-56-7890'),
    ('Charlie Brown', 'charlie@acme.com', '345-67-8901'),
    ('Diana Prince', 'diana@acme.com', '456-78-9012'),
    ('Ethan Hunt', 'ethan@acme.com', '567-89-0123'),
    ('Fiona Gallagher', 'fiona@acme.com', '678-90-1234'),
    ('George Costanza', 'george@acme.com', '789-01-2345'),
    ('Hannah Abbott', 'hannah@acme.com', '890-12-3456'),
    ('Ian Malcolm', 'ian@acme.com', '901-23-4567'),
    ('Julia Child', 'julia@acme.com', '012-34-5678'),
    ('Kevin McCallister', 'kevin@acme.com', '123-11-2222'),
    ('Luna Lovegood', 'luna@acme.com', '234-22-3333'),
    ('Michael Scott', 'michael@acme.com', '345-33-4444'),
    ('Nancy Drew', 'nancy@acme.com', '456-44-5555'),
    ('Oscar Martinez', 'oscar@acme.com', '567-55-6666'),
    ('Pam Beesly', 'pam@acme.com', '678-66-7777'),
    ('Quentin Tarantino', 'quentin@acme.com', '789-77-8888'),
    ('Rachel Green', 'rachel@acme.com', '890-88-9999'),
    ('Steve Harrington', 'steve@acme.com', '901-99-0000'),
    ('Tony Stark', 'tony@acme.com', '012-00-1111'),
    ('Ursula Buffay', 'ursula@acme.com', '123-99-8888'),
    ('Victor Frankenstein', 'victor@acme.com', '234-88-7777'),
    ('Wanda Maximoff', 'wanda@acme.com', '345-77-6666');

INSERT INTO orders (user_id, amount) VALUES
    (1, 150.00), (1, 25.50), (2, 99.99), (3, 450.00), (5, 12.00);
