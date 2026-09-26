import os
import mysql.connector

MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
MYSQL_USER = os.getenv("MYSQL_USER", "root")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "")
MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "credential_assessment")


def get_database_connection():
    return mysql.connector.connect(
        host=MYSQL_HOST, user=MYSQL_USER, password=MYSQL_PASSWORD, database=MYSQL_DATABASE
    )


def initialize_database():
    server = mysql.connector.connect(host=MYSQL_HOST, user=MYSQL_USER, password=MYSQL_PASSWORD)
    cursor = server.cursor()
    cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{MYSQL_DATABASE}`")
    cursor.close(); server.close()

    connection = get_database_connection()
    cursor = connection.cursor()

    cursor.execute("""CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(150) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(20) NOT NULL DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS assessment_results (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NULL, score INT NOT NULL,
        readiness_level VARCHAR(50) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_assessment_user (user_id)
    )""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS exposure_checks (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL, email_checked VARCHAR(150) NOT NULL,
        status VARCHAR(100) NOT NULL, checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_exposure_user (user_id)
    )""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS credential_exposure_checks (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        sha1_prefix CHAR(5) NOT NULL,
        exposed BOOLEAN NOT NULL DEFAULT FALSE,
        match_count INT NOT NULL DEFAULT 0,
        checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_credential_user (user_id)
    )""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS audit_logs (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NULL,
        action VARCHAR(100) NOT NULL,
        target_type VARCHAR(50) NOT NULL,
        target_id VARCHAR(100) NULL,
        ip_address VARCHAR(45) NULL,
        user_agent VARCHAR(500) NULL,
        metadata_json TEXT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_audit_user (user_id),
        INDEX idx_audit_created (created_at)
    )""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS request_metrics (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        method VARCHAR(10) NOT NULL,
        path VARCHAR(255) NOT NULL,
        status_code INT NOT NULL,
        response_time_ms DECIMAL(10,2) NULL,
        error_message VARCHAR(500) NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_metrics_created (created_at)
    )""")
    connection.commit()
    cursor.close(); connection.close()
