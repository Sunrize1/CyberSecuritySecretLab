CREATE DATABASE IF NOT EXISTS secret_lab CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE secret_lab;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE research_data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    encrypted_content TEXT NOT NULL,
    encryption_key VARCHAR(255) NOT NULL,
    researcher_id INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (researcher_id) REFERENCES users(id)
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE admin_secrets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    secret_name VARCHAR(255) NOT NULL,
    secret_value TEXT NOT NULL,
    access_level VARCHAR(20) DEFAULT 'admin'
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Вставляем тестовых пользователей
INSERT INTO users (username, password, role) VALUES 
('researcher1', 'research_pass', 'user'),
('lab_assistant', 'assistant123', 'user'),
('guest', 'guest_password', 'guest');

-- Вставляем зашифрованные исследования с шифром Цезаря
INSERT INTO research_data (title, encrypted_content, encryption_key, researcher_id) VALUES 
('Проект Альфа - Классификация', 'ZLJYLA SHIVYHAVYF YLZLHYJO WYVQLKA HSWOH

JSHZZVMPJHAPVU: AVW ZLJYLA
LEWLYPTLUA PK: SHI-2025-001
YLZLHYJOLY: KY. ZTPAO

VIQLJAPCL: KLCLSVW HKCHUJLK LUJYFWAPVU TLAOVKZ MVY ZLJBYL KHAH AYHUZTVZZPVU

MPUKPUNZ:
- JBYYLUA JHLZHY JPWOLY PTWSLTLUAHAPVU PZ CBSULYHISL
- MYLXBLUJF HUHSFZPZ YLCLHSZ WHAALUZ
- YLJVTTLUK BWNYKHPUN AV HLZ-256 LUJYFWAPVU
- RLF THUHNLTLUA ZFZALT ULLKZ PTWYVCTLUA

ZLJBYPAF UVLZ:
- AOPZ KVJBTLUA JVUAHPUZ JSHZZVMPLK PUMVYTHAPVU
- BUHABOVYPGLK HJJLZZ PZ WYVOPIPALK
- YLWVYA HUF ZLJBYPAF IYLHJOLZ PTTLKPHALSF

LUK VM KVJBTLUA', 'Шифр Цезаря со сдвигом 7. Попробуйте разные значения сдвига.', 1);


INSERT INTO admin_secrets (secret_name, secret_value, access_level) VALUES 
('admin_flag', 'HITS{pr1v1l3g3_3sc4l4t10n}', 'admin'),
('crypto_flag', 'HITS{cr7pt0_k3y_r3v3rs3d}', 'admin'),
('sql_flag', 'HITS{web_1nj3ct10n_m4st3r}', 'admin'),
('database_credentials', 'mysql://lab_user:lab_password_456@db:3306/secret_lab', 'admin'),
('jwt_secret', 'weak_jwt_secret_1234567891234567', 'admin'); 