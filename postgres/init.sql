-- Crear una tabla de usuarios
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    passwrd VARCHAR(255) NOT NULL, -- Corregido el nombre de la columna
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE public_keys (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    public_key TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE files (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    file_name VARCHAR(255) NOT NULL,
    file_data BYTEA NOT NULL,
    file_hash TEXT NOT NULL,
    hash_alg VARCHAR (255),
    file_size VARCHAR (255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE signatures (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    file_id INT REFERENCES files(id) ON DELETE CASCADE,
    file_signature TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insertar datos iniciales
INSERT INTO users (email, passwrd) VALUES
('admin@example.com', 'adminpassword'),
('user@example.com', 'userpassword');








