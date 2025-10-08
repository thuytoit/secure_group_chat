from src.groups import GroupManager
from src.users import login
gm = GroupManager()

# Sim tokens
_, admin_token, _ = login('admin', 'adminpass')
success, key, msg = gm.add_user('testuser', admin_token)
print("Add:", success, msg, "Key len:", len(key) if key else 0)

success, new_key, msg = gm.kick_user('testuser', admin_token)
print("Kick:", success, msg, "New key != old?", new_key != key)