#DROP DATABASE sierra_budget;

CREATE DATABASE sierra_budget;

USE sierra_budget;


CREATE TABLE budget_codes (
	id INT AUTO_INCREMENT PRIMARY KEY,
       	email VARCHAR(100) NOT NULL,
	code VARCHAR(100) NOT NULL,
	description VARCHAR(200)
);



-- We should dynamically create these statements from the config file
-- so we get the correct hostname.

GRANT SELECT,INSERT on sierra_budget.* TO sierrauser@localhost;

FLUSH PRIVILEGES;

