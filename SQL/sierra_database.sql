#DROP DATABASE sierra;

CREATE DATABASE sierra;

USE sierra;


CREATE TABLE person (
	id INT AUTO_INCREMENT PRIMARY KEY,
       	first_name VARCHAR(50),
       	last_name VARCHAR(50),
       	email VARCHAR(100) UNIQUE NOT NULL,
       	phone VARCHAR(50),
	anonymous BOOLEAN,
	is_admin BOOLEAN,
	password VARCHAR(100)
);

CREATE TABLE person_permission (
	id INT AUTO_INCREMENT PRIMARY KEY,
       	owner_person_id INT,
	permission_person_id INT,
	KEY (owner_person_id),
	KEY (permission_person_id)
);

CREATE TABLE password_reset (
	id INT AUTO_INCREMENT PRIMARY KEY,
	person_id INT UNIQUE,
	date DATETIME,
	secret VARCHAR(50),
	password VARCHAR(100),
	KEY (person_id),
	KEY (date)
);

CREATE TABLE sample (
	id INT AUTO_INCREMENT PRIMARY KEY,
	person_id INT,
	sample_type_id INT,
	users_sample_name VARCHAR(50),
	lanes_required INT,
	submitted_date DATETIME,
	received_by_person_id INT,
	received_date DATETIME,
	passed_individual_qc_date DATETIME,
	passed_qc_date DATETIME,
	run_type_id INT,
	adapter_id INT,
	search_database_id INT,
	is_suitable_control BOOLEAN,
	budget_code VARCHAR(100),
	is_complete boolean NOT NULL DEFAULT '0',
	KEY (person_id),
	KEY (sample_type_id),
	KEY (users_sample_name),
	KEY (submitted_date),
	KEY (received_by_person_id),
	KEY (run_type_id),
	KEY (adapter_id),
	KEY (received_date),
	KEY (passed_qc_date),
	KEY (passed_individual_qc_date),
	KEY (budget_code),
	KEY (search_database_id),
	KEY (is_suitable_control),
	KEY (is_complete)	
);

CREATE TABLE sample_permission (
	id INT AUTO_INCREMENT PRIMARY KEY,
       	sample_id INT,
	permission_person_id INT,
	KEY (sample_id),
	KEY (permission_person_id)
);

CREATE TABLE sample_auth_key (
	id INT AUTO_INCREMENT PRIMARY KEY,
       	sample_id INT,
	person_id INT,
	authkey VARCHAR(50),
	message VARCHAR(200),
	KEY (sample_id),
	KEY (person_id),
	KEY (authkey)
);

CREATE TABLE sample_note (
	id INT AUTO_INCREMENT PRIMARY KEY,
	sample_id INT,
	person_id INT,
	date DATETIME,
	note TEXT,
	filename VARCHAR(200),
	KEY (sample_id),
	KEY (date)
);

CREATE TABLE sample_type (
	id INT AUTO_INCREMENT PRIMARY KEY,
	name VARCHAR(100),
	description VARCHAR(200),
	retired BOOLEAN NOT NULL DEFAULT '0',
	KEY (retired)
);

CREATE TABLE flowcell (
	id INT AUTO_INCREMENT PRIMARY KEY,
	serial_number VARCHAR(50) UNIQUE,
	run_type_id INT,
	run_id INT,
	available_lanes INT,
	KEY (run_id)
);

CREATE TABLE lane (
	id INT AUTO_INCREMENT PRIMARY KEY,
	flowcell_id INT,
	sample_id INT,
	lane_number INT,
	use_as_control BOOLEAN,
	KEY (flowcell_id),
	KEY (sample_id)
);

CREATE TABLE barcode (
	id INT AUTO_INCREMENT PRIMARY KEY,
	sample_id INT,
	5_prime_barcode VARCHAR(50),
	3_prime_barcode VARCHAR(50),
	name VARCHAR(200),
	KEY (sample_id)
);

CREATE TABLE instrument (
	id INT AUTO_INCREMENT PRIMARY KEY,
	serial_number VARCHAR(50),
	description VARCHAR(200),
	retired BOOLEAN,
	available BOOLEAN,
	message VARCHAR(200)
);

CREATE TABLE adapter (
	id INT AUTO_INCREMENT PRIMARY KEY,
	name VARCHAR(200),
	retired BOOLEAN
);

CREATE TABLE run_type (
	id INT AUTO_INCREMENT PRIMARY KEY,
	name VARCHAR(100),
	lanes INT,
	retired BOOLEAN NOT NULL DEFAULT '0',
	KEY (retired)
);

CREATE TABLE run_type_instrument (
	id INT AUTO_INCREMENT PRIMARY KEY,
	run_type_id INT,
	instrument_id INT,
	use_as_control BOOLEAN,
	KEY (run_type_id),
	KEY (instrument_id)
);

CREATE TABLE search_database (
	id INT AUTO_INCREMENT PRIMARY KEY,
	species VARCHAR(100),
	assembly VARCHAR(50),
	folder VARCHAR(200)
);

CREATE TABLE run (
	id INT AUTO_INCREMENT PRIMARY KEY,
	flowcell_id INT,
	instrument_id INT,
	date DATETIME,
	run_folder_name VARCHAR(100),
	KEY (flowcell_id),
	KEY (instrument_id),
	KEY (date)
);

-- We should dynamically create these statements from the config file
-- so we get the correct hostname.

CREATE USER sierrauser@localhost IDENTIFIED BY "";
GRANT INSERT,SELECT on sierra.* TO sierrauser@localhost;
GRANT DELETE on sierra.password_reset TO sierrauser@localhost;
GRANT DELETE on sierra.lane TO sierrauser@localhost;
GRANT UPDATE on sierra.person TO sierrauser@localhost;
GRANT UPDATE on sierra.sample TO sierrauser@localhost;
GRANT UPDATE,DELETE on sierra.flowcell TO sierrauser@localhost;
GRANT UPDATE on sierra.instrument TO sierrauser@localhost;
GRANT DELETE on sierra.run_type_instrument TO sierrauser@localhost;
GRANT UPDATE on sierra.run_type TO sierrauser@localhost;
GRANT UPDATE on sierra.run TO sierrauser@localhost;
GRANT UPDATE on sierra.sample_type TO sierrauser@localhost;
GRANT UPDATE on sierra.search_database TO sierrauser@localhost;
GRANT DELETE on sierra.person_permission TO sierrauser@localhost;
GRANT DELETE on sierra.sample_auth_key TO sierrauser@localhost;
GRANT DELETE on sierra.barcode TO sierrauser@localhost;
GRANT DELETE on sierra.sample_note TO sierrauser@localhost;

FLUSH PRIVILEGES;

