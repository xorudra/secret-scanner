import httpx
import re

resp = httpx.get('http://localhost:8000/')
html = resp.text

# Check for page- elements
pages = re.findall(r'id="page-[^"]*"', html)
for p in pages:
    print(p)