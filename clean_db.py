#!/usr/bin/env python3
import os
from pathlib import Path

# Delete database
db_path = Path(__file__).parent / 'src' / 'chat.db'
if db_path.exists():
    os.remove(db_path)
    print(f"✓ Deleted {db_path}")

# Delete users file  
#users_path = Path(__file__).parent / 'src' / 'users.json'
#if users_path.exists():
#    os.remove(users_path)
#    print(f"✓ Deleted {users_path}")

# Delete any .db-shm and .db-wal files
for ext in ['-shm', '-wal']:
    wal_path = Path(__file__).parent / 'src' / f'chat.db{ext}'
    if wal_path.exists():
        os.remove(wal_path)
        print(f"✓ Deleted {wal_path}")

print("\n✅ All clean! Ready for fresh test.")
print("Now run: python src/app.py")