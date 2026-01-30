import json

try:
    with open('api_docs.json', 'r') as f:
        data = json.load(f)
    print(json.dumps(data.get('securityDefinitions', {}), indent=2))
except Exception as e:
    print(e)
