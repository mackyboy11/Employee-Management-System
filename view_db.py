import sqlite3
import os

# Use absolute path
db_path = os.path.join(os.getcwd(), 'company.db')
print(f"Database path: {db_path}")
print(f"Database exists: {os.path.exists(db_path)}")

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# List all tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = cursor.fetchall()
print(f"\nAvailable tables: {tables}")

if not tables:
    print("\n No tables found. The database is empty.")
    print("Make sure the Flask app is running and has created the tables.")
else:
    for table in tables:
        table_name = table[0]
        print(f'\n=== {table_name.upper()} TABLE ===')
        cursor.execute(f'PRAGMA table_info({table_name})')
        columns = cursor.fetchall()
        col_names = [col[1] for col in columns]
        print(f"Columns: {col_names}")
        
        cursor.execute(f'SELECT * FROM {table_name}')
        rows = cursor.fetchall()
        
        if rows:
            for row in rows:
                print(row)
        else:
            print("(No data)")

conn.close()
