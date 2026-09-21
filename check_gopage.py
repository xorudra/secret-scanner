import httpx

resp = httpx.get('http://localhost:8000/')
html = resp.text

# Extract the script section
idx = html.find('<script>')
if idx >= 0:
    script = html[idx:idx+5000]
    # Check the goPage function
    go_idx = script.find('function goPage')
    if go_idx >= 0:
        with open('goPage_check.txt', 'w', encoding='utf-8') as f:
            f.write(script[go_idx:go_idx+500])
        print('Written to goPage_check.txt')