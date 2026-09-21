import httpx
import re

resp = httpx.get('http://localhost:8000/')
print('Status:', resp.status_code)
html = resp.text

# Check for JavaScript errors by looking at the script
if 'function goPage' in html:
    print('goPage function: FOUND')
else:
    print('goPage function: MISSING')

# Check if onclick handlers are present
onclicks = re.findall(r'onclick="goPage\([^)]+\)"', html)
print('onclick handlers:', len(onclicks))

# Check for any console.error or try/catch
if 'console.error' in html:
    print('Has console.error: YES')
else:
    print('Has console.error: NO')

# Check the DOMContentLoaded wrapper
if 'DOMContentLoaded' in html:
    print('DOMContentLoaded wrapper: FOUND')
else:
    print('DOMContentLoaded wrapper: MISSING')

# Check if elements exist when script runs
print('nav-path in HTML:', 'id="nav-path"' in html)
print('page-path in HTML:', 'id="page-path"' in html)