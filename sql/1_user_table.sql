USE personal_finance_app;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,        
    nickname VARCHAR(255) NOT NULL,            
    email VARCHAR(255) NOT NULL UNIQUE,       
    password VARCHAR(255) NOT NULL
);

ALTER TABLE users ADD reset_token VARCHAR(255);
ALTER TABLE users ADD reset_token_expiration DATETIME;

SELECT * FROM users;


