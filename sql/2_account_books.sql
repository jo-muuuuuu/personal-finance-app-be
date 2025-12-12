USE penny_wave_db;

CREATE TABLE account_books (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    name VARCHAR(255) NOT NULL,
    tag VARCHAR(255),
    description TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

ALTER TABLE account_books ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

SELECT * FROM account_books;
