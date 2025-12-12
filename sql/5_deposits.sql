USE penny_wave_db;

CREATE TABLE deposits (
    id INT AUTO_INCREMENT PRIMARY KEY,
    plan_id INT NOT NULL,
    user_id INT NOT NULL,
    scheduled_amount DECIMAL(10,2) NOT NULL,
    deposited_amount DECIMAL(10,2) NOT NULL,
    date DATE NOT NULL,
    status ENUM('pending', 'completed') DEFAULT 'completed',

    FOREIGN KEY (plan_id) REFERENCES savings_plans(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

SELECT * FROM deposits;
