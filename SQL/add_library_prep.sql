
CREATE TABLE library_prep (
       id INT AUTO_INCREMENT PRIMARY KEY,
       name VARCHAR(200),
       allows_subsamples BOOLEAN,
       require_prep BOOLEAN,
       retired BOOLEAN NOT NULL DEFAULT 0       	
);

INSERT INTO library_prep (name,allows_subsamples,require_prep) VALUES ("Pre-prepared library",1,0);

ALTER TABLE sample ADD library_prep_id INT NOT NULL DEFAULT 1;

ALTER TABLE sample ADD KEY library_prep_id (library_prep_id);


ALTER TABLE barcode ADD passed_qc BOOLEAN NOT NULL DEFAULT 1;

ALTER TABLE barcode ADD KEY passed_qc (passed_qc);



