USE penny_wave_db;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,        
    nickname VARCHAR(255) NOT NULL,            
    email VARCHAR(255) NOT NULL UNIQUE,       
    password VARCHAR(255) NOT NULL
);

ALTER TABLE users ADD reset_token VARCHAR(255);
ALTER TABLE users ADD reset_token_expiration DATETIME;
ALTER TABLE users ADD avatar_url VARCHAR(512);

SELECT * FROM users;


