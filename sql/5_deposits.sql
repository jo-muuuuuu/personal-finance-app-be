USE personal_finance_app;

CREATE TABLE deposits (
    id INT AUTO_INCREMENT PRIMARY KEY,
    plan_id INT NOT NULL,
    user_id INT NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    date DATE NOT NULL,
    status ENUM('pending', 'completed') DEFAULT 'completed',

    FOREIGN KEY (plan_id) REFERENCES saving_plans(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

SELECT * FROM deposits;
