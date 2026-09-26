"""Optional local database connectivity check; credentials come from environment variables."""
import os
import mysql.connector

def get_database_connection():
    return mysql.connector.connect(
        host=os.getenv("MYSQL_HOST", "localhost"),
        user=os.getenv("MYSQL_USER", "root"),
        password=os.getenv("MYSQL_PASSWORD", ""),
        database=os.getenv("MYSQL_DATABASE", "credential_assessment"),
    )

if __name__ == "__main__":
    connection = get_database_connection()
    print("MySQL Database Connected Successfully!")
    connection.close()
