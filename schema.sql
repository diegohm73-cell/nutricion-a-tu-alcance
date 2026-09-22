-- Esquema lógico equivalente al creado por main.py.
CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE profiles (
  user_id INTEGER PRIMARY KEY,
  payload TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE menus (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL,
  title TEXT,
  goal TEXT,
  kcal INTEGER,
  protein INTEGER,
  meals INTEGER,
  payload TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE tracking (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL,
  energy INTEGER,
  hunger INTEGER,
  sleep INTEGER,
  digestion INTEGER,
  adherence INTEGER,
  created_at TEXT NOT NULL
);

CREATE TABLE subscriptions (
  user_id INTEGER PRIMARY KEY,
  plan TEXT NOT NULL,
  status TEXT NOT NULL,
  provider TEXT,
  provider_customer_id TEXT,
  provider_subscription_id TEXT,
  renews_at TEXT,
  updated_at TEXT NOT NULL
);
