with open('secret_scanner/api/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

old = '''        return v


class ScanResponse(BaseModel):'''
new = '''        return v


class RuleCreateRequest(BaseModel):
    id: str
    name: str
    pattern: str
    severity: str
    description: str = \"\"


class ScanResponse(BaseModel):'''

content = content.replace(old, new)

with open('secret_scanner/api/app.py', 'w', encoding='utf-8') as f:
    f.write(content)
print('Model added')