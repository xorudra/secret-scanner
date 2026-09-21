import httpx
import re

resp = httpx.get('http://localhost:8000/')
html = resp.text

# Check the nav items
nav_items = re.findall(r'<button[^>]*id="nav-[^"]*"[^>]*>', html)
for item in nav_items:
    print(item)