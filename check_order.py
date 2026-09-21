import httpx

resp = httpx.get('http://localhost:8000/')
html = resp.text

# Find where the script is in relation to the nav buttons
script_idx = html.find('<script>')
nav_idx = html.find('id="nav-path"')

print('Script at:', script_idx)
print('Nav at:', nav_idx)

if script_idx < nav_idx:
    print('Script is BEFORE nav (script executes first)')
else:
    print('Script is AFTER nav (nav exists first)')