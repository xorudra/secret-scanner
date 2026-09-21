import httpx

resp = httpx.get('http://localhost:8000/')
html = resp.text

# Find the script tag and surrounding context
script_idx = html.find('<script>')
context = html[script_idx-200:script_idx+100]

with open('script_context.txt', 'w', encoding='utf-8') as f:
    f.write(context)
print('Written to script_context.txt')