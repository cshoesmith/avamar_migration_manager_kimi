import sqlite3
import json
from avamar_client import AvamarClient
from settings_manager import SettingsManager

def repair_unknowns():
    conn = sqlite3.connect('migration_status.db')
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    
    # Find Unknowns
    cur.execute("SELECT * FROM migrated_clients WHERE client_name = 'Unknown'")
    unknowns = cur.fetchall()
    
    if not unknowns:
        print("No 'Unknown' clients found.")
        return

    print(f"Found {len(unknowns)} unknown clients. Attempting repair...")
    
    settings = SettingsManager()
    
    # Cache connections
    connections = {}
    
    for row in unknowns:
        job_id = row['job_id']
        cid = row['client_cid']
        client_id = row['id']
        
        # Get Source Host from Job
        cur.execute("SELECT source_system FROM replication_jobs WHERE id = ?", (job_id,))
        job = cur.fetchone()
        if not job:
            print(f"Skipping client {client_id}: Job {job_id} not found.")
            continue
            
        host = job['source_system']
        
        # Get Client Connection
        client = connections.get(host)
        if not client:
            src_config = next((s for s in settings.get_sources() if s['host'] == host), None)
            if src_config:
                try:
                    pw = settings._decrypt(src_config['password'])
                    client = AvamarClient(host, src_config['user'], pw)
                    client._authenticate()
                    connections[host] = client
                except Exception as e:
                    print(f"Failed to connect to {host}: {e}")
                    continue
        
        if client:
            try:
                print(f"Fetching details for CID {cid} from {host}...")
                # Use our new method
                details = client.get_client_by_id(cid)
                if details:
                    real_name = details.get('name')
                    real_domain = details.get('domainFqdn') or details.get('domain')
                    
                    if real_name:
                        cur.execute(
                            "UPDATE migrated_clients SET client_name = ?, client_domain = ? WHERE id = ?",
                            (real_name, real_domain, client_id)
                        )
                        conn.commit()
                        print(f"  Fixed! -> {real_name} ({real_domain})")
                    else:
                        print("  Response missing name.")
                else:
                    print("  Client not found on source.")
            except Exception as e:
                print(f"  Error fetching/updating: {e}")

    conn.close()
    print("Repair complete.")

if __name__ == "__main__":
    repair_unknowns()
