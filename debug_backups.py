
import json
from avamar_client import AvamarClient
from settings_manager import SettingsManager

settings = SettingsManager()
sources = settings.get_sources()
if not sources: exit()
s = sources[0]
pw = settings._decrypt(s['password'])
client = AvamarClient(s['host'], s['user'], pw)
client._authenticate()

clients = client.get_clients(domain='/')
if not clients: exit()

# Loop until we find one with backups
found = False
for target in clients:
    print(f"Checking {target['name']}...")
    backups = client.get_client_backups(target['id'])
    if backups:
        print(f"FOUND BACKUPS for {target['name']}")
        print(json.dumps(backups[0], indent=2))
        found = True
        break
    
if not found:
    print("No backups found for ANY client")
