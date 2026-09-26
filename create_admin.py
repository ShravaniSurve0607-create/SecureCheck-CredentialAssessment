import os
from getpass import getpass
from database import get_database_connection, initialize_database
from werkzeug.security import generate_password_hash

initialize_database()
name = input("Admin name: ").strip()
email = input("Admin email: ").strip().lower()
password = getpass("Admin password: ")
conn = get_database_connection()
cur = conn.cursor()
cur.execute("""INSERT INTO users (name,email,password,role)
               VALUES (%s,%s,%s,'admin')""",
            (name,email,generate_password_hash(password)))
conn.commit()
cur.close(); conn.close()
print("Admin created.")
