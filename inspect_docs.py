import json

try:
    with open('api_docs.json', 'r') as f:
        data = json.load(f)
    
    print("Top level keys:", list(data.keys()))
    
    if 'paths' in data:
        print(f"Number of paths: {len(data['paths'])}")
        print("\nReplication related paths:")
        for path in data['paths']:
            if 'replication' in path.lower():
                print(path)
        
        print("\nClient related paths (first 10):")
        count = 0
        for path in data['paths']:
            if 'client' in path.lower():
                print(path)
                count += 1
                if count >= 10: break

        print("\nBackup related paths (first 10):")
        count = 0
        for path in data['paths']:
            if 'backup' in path.lower() and 'group' not in path.lower(): # trying to find backup listings
                print(path)
                count += 1
                if count >= 10: break

        print("\nGroup related paths (first 10):")
        count = 0
        for path in data['paths']:
            if 'group' in path.lower():
                print(path)
                count += 1
                if count >= 10: break

except Exception as e:
    print(f"Error reading JSON: {e}")
