USE personal_finance_app;

CREATE TABLE saving_plans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    amount DECIMAL(10,2) NOT NULL,
    period ENUM('week', 'fortnight', 'month', 'quarter', 'year') NOT NULL,
    total_periods INT NOT NULL,
    completed_periods INT DEFAULT 0,
    amount_per_period DECIMAL(10,2) NOT NULL,
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    status ENUM('active', 'paused', 'completed', 'cancelled') DEFAULT 'active',

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

ALTER TABLE saving_plans ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE saving_plans ADD COLUMN deposited_amount DECIMAL(10,2) DEFAULT 0.00 AFTER amount_per_period;


SELECT * FROM saving_plans;