USE personal_finance_app;

CREATE TABLE transactions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    account_book_id INT NOT NULL,
    amount DECIMAL(10, 2) NOT NULL,
    category VARCHAR(255),
    description TEXT,
    date DATE NOT NULL,
    type ENUM('income', 'expense') NOT NULL,  
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (account_book_id) REFERENCES account_books(id) ON DELETE CASCADE
);

ALTER TABLE transactions ADD account_book_name VARCHAR(255) AFTER account_book_id;

SELECT * FROM transactions;
