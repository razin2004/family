import sqlite3

conn = sqlite3.connect("family.db")
cur = conn.cursor()


# USERS table
cur.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    name TEXT,
    selfie_path TEXT,
    role TEXT,
    is_verified INTEGER,
    is_approved INTEGER
);
""")

# OTPS table
cur.execute("""
CREATE TABLE IF NOT EXISTS otps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT,
    otp_code TEXT
);
""")

# FAMILY MEMBERS table
cur.execute("DROP TABLE IF EXISTS family_members")
cur.execute("""
CREATE TABLE family_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    is_late INTEGER DEFAULT 0,
    dob TEXT,
    gender TEXT,
    blood_group TEXT,
    job_or_education TEXT,
    selfie_path TEXT
);

""")

# RELATIONSHIPS table
cur.execute("DROP TABLE IF EXISTS relationships")
cur.execute("""
CREATE TABLE relationships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id INTEGER,
    relation TEXT,           
    related_to INTEGER,
    FOREIGN KEY(member_id) REFERENCES family_members(id),
    FOREIGN KEY(related_to) REFERENCES family_members(id)
);
""")

conn.commit()
conn.close()

print("All tables created successfully.")
