import httpx

resp = httpx.get('http://localhost:8000/')
html = resp.text

# Find the script
idx = html.find('<script>')
if idx >= 0:
    script = html[idx:]
    end_idx = script.find('</script>')
    if end_idx >= 0:
        script = script[:end_idx]
        
        # Check if wrapped in DOMContentLoaded
        if 'DOMContentLoaded' in script:
            wrap_idx = script.find('DOMContentLoaded')
            with open('dom_check.txt', 'w', encoding='utf-8') as f:
                f.write(script[max(0,wrap_idx-300):wrap_idx+500])
            print('Written to dom_check.txt')