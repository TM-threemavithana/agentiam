import os
import sys
import psycopg2
from psycopg2.extras import execute_values
import random
import time

NEON_DSN = os.getenv("NEON_DSN")

if not NEON_DSN:
    print("❌ NEON_DSN environment variable not set.")
    print("Usage: NEON_DSN='postgres://user:pass@ep-cool-db.neon.tech/neondb' python seed_neon.py")
    sys.exit(1)

SCHEMA_SQL = """
DROP TABLE IF EXISTS reviews CASCADE;
DROP TABLE IF EXISTS order_items CASCADE;
DROP TABLE IF EXISTS orders CASCADE;
DROP TABLE IF EXISTS products CASCADE;
DROP TABLE IF EXISTS users CASCADE;

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    lifetime_value DECIMAL(10, 2) DEFAULT 0.00
);

CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    category VARCHAR(100) NOT NULL,
    price DECIMAL(10, 2) NOT NULL,
    stock_quantity INT DEFAULT 0
);

CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    total_amount DECIMAL(10, 2) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE order_items (
    id SERIAL PRIMARY KEY,
    order_id INT REFERENCES orders(id) ON DELETE CASCADE,
    product_id INT REFERENCES products(id),
    quantity INT NOT NULL,
    unit_price DECIMAL(10, 2) NOT NULL
);

CREATE TABLE reviews (
    id SERIAL PRIMARY KEY,
    product_id INT REFERENCES products(id) ON DELETE CASCADE,
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    rating INT CHECK (rating >= 1 AND rating <= 5),
    comment TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_orders_user_id ON orders(user_id);
CREATE INDEX idx_order_items_order_id ON order_items(order_id);
CREATE INDEX idx_reviews_product_id ON reviews(product_id);
"""

print(f"🔌 Connecting to Neon...")
conn = psycopg2.connect(NEON_DSN)
cur = conn.cursor()

print("🏗️ Creating complex e-commerce schema...")
cur.execute(SCHEMA_SQL)
conn.commit()

# Constants for generating heavy data
NUM_USERS = 50_000
NUM_PRODUCTS = 10_000
NUM_ORDERS = 250_000
NUM_REVIEWS = 100_000

print(f"🌱 Seeding {NUM_USERS} Users...")
users_data = []
for i in range(1, NUM_USERS + 1):
    users_data.append((f"user_{i}", f"user{i}@example.com", random.uniform(0, 1000)))
execute_values(cur, "INSERT INTO users (username, email, lifetime_value) VALUES %s", users_data, page_size=1000)
conn.commit()

print(f"📦 Seeding {NUM_PRODUCTS} Products...")
categories = ["Electronics", "Books", "Home", "Garden", "Toys", "Sports"]
products_data = []
for i in range(1, NUM_PRODUCTS + 1):
    products_data.append((f"Product {i}", random.choice(categories), round(random.uniform(5.0, 500.0), 2), random.randint(0, 1000)))
execute_values(cur, "INSERT INTO products (name, category, price, stock_quantity) VALUES %s", products_data, page_size=1000)
conn.commit()

print(f"🛒 Seeding {NUM_ORDERS} Orders and Order Items...")
orders_data = []
for i in range(1, NUM_ORDERS + 1):
    user_id = random.randint(1, NUM_USERS)
    total_amount = round(random.uniform(10.0, 1500.0), 2)
    status = random.choice(["pending", "shipped", "delivered", "cancelled"])
    orders_data.append((user_id, total_amount, status))

execute_values(cur, "INSERT INTO orders (user_id, total_amount, status) VALUES %s", orders_data, page_size=2000)
conn.commit()

print("📝 Seeding Order Items...")
# We assume order IDs start at 1
items_data = []
for order_id in range(1, NUM_ORDERS + 1):
    num_items = random.randint(1, 5)
    for _ in range(num_items):
        product_id = random.randint(1, NUM_PRODUCTS)
        qty = random.randint(1, 4)
        price = round(random.uniform(5.0, 500.0), 2)
        items_data.append((order_id, product_id, qty, price))
execute_values(cur, "INSERT INTO order_items (order_id, product_id, quantity, unit_price) VALUES %s", items_data, page_size=5000)
conn.commit()

print(f"⭐ Seeding {NUM_REVIEWS} Reviews...")
reviews_data = []
for i in range(NUM_REVIEWS):
    product_id = random.randint(1, NUM_PRODUCTS)
    user_id = random.randint(1, NUM_USERS)
    rating = random.randint(1, 5)
    comment = "Great product!" if rating >= 4 else "Could be better."
    reviews_data.append((product_id, user_id, rating, comment))
execute_values(cur, "INSERT INTO reviews (product_id, user_id, rating, comment) VALUES %s", reviews_data, page_size=5000)
conn.commit()

print("✅ Data seeding complete! You now have a heavy dataset to test AST recursion and TCP streams.")
cur.close()
conn.close()
