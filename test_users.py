from src.users import register, login, is_admin, logout

# Register
success, msg = register('testuser', 'testpass')
print("Register:", success, msg)

# Login
success, token, role = login('testuser', 'testpass')
print("Login:", success, token[:20] + "...", role)  # Token truncated

# Admin
success, admin_token, admin_role = login('admin', 'adminpass')
print("Admin login:", success, admin_role)
print("Is admin?", is_admin(admin_token))

# Logout
logout(token)
logout(admin_token)
print("Logged out.")