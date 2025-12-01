# Run this script to fix routes.py
# python fix_routes.py

import shutil

# Create backup
shutil.copy('app/routes.py', 'app/routes.py.backup')
print("✅ Backup created: app/routes.py.backup")

# Read the routes_fix.py content
with open('routes_fix.py', 'r', encoding='utf-8') as f:
    fix_content = f.read()

# Read the current routes.py up to line 482
with open('app/routes.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Take only the first 482 lines (everything before the corrupted section)
good_content = ''.join(lines[:482])

# Combine good content with fix
new_content = good_content + '\n' + fix_content

# Write back
with open('app/routes.py', 'w', encoding='utf-8') as f:
    f.write(new_content)

print("✅ routes.py fixed successfully!")
print("The file now has the corrected code without duplicates.")
print("You can delete routes_fix.py and this script  after confirming it works.")
