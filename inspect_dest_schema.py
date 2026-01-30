import json

try:
    with open('api_docs.json', 'r') as f:
        data = json.load(f)
    
    print("\n\nSchema for POST /v1/replication/destinations:")
    try:
        post_method = data['paths']['/v1/replication/destinations']['post']
        for param in post_method.get('parameters', []):
            if param['in'] == 'body':
                schema = param['schema']
                print(json.dumps(schema, indent=2))
                # Print the definition if it's a ref
                if '$ref' in schema:
                    ref = schema['$ref'].split('/')[-1]
                    print(f"\nDefinition {ref}:")
                    print(json.dumps(data['definitions'].get(ref, {}), indent=2))

    except KeyError:
        print("POST /v1/replication/destinations not found")

except Exception as e:
    print(f"Error: {e}")
