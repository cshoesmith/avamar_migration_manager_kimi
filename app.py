from flask import Flask, render_template, jsonify, request, make_response, redirect, url_for, flash
from avamar_client import AvamarClient
from settings_manager import SettingsManager
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash
from functools import wraps
from datetime import datetime
from dotenv import load_dotenv
import database
import os
import re

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')
if not app.secret_key:
    raise ValueError("SECRET_KEY environment variable must be set") 
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role
        
@login_manager.user_loader
def load_user(user_id):
    u = database.get_user_by_id(user_id)
    if u:
        return User(u['id'], u['username'], u['role'])
    return None

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
             if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
                 return jsonify({'error': 'Admin privileges required'}), 403
             else: # If they accessed a page directly
                 return "Admin privileges required", 403
        return f(*args, **kwargs)
    return decorated_function

settings = SettingsManager()

# In-memory cache for scan results (refreshed on each scan)
candidates_cache = []


def get_client_for_host(host, is_source=True):
    """Helper to get authenticated AvamarClient for a given host."""
    candidates = settings.get_sources() if is_source else settings.get_destinations()
    for conf in candidates:
        if conf['host'] == host:
            try:
                pw = settings._decrypt(conf['password'])
                role = 'source' if is_source else 'destination'
                cl = AvamarClient(host, conf['user'], pw, role=role)
                if cl._authenticate():
                    return cl
            except Exception as e:
                app.logger.warning(f"Failed to authenticate to {host}: {e}")
                continue
    return None


def strip_passwords(data_list):
    """Remove password fields from config dictionaries for API responses."""
    return [{k: v for k, v in item.items() if k != 'password'} for item in data_list]


def calculate_backup_size(backup_list):
    """Calculate total size in bytes from a list of backup objects."""
    total_bytes = 0
    try:
        for b in backup_list:
            val = b.get('totalBytes') or b.get('totalbytes') or b.get('size') or b.get('bytes') or 0
            try:
                total_bytes += int(val)
            except (ValueError, TypeError):
                pass
    except Exception as e:
        app.logger.warning(f"Error calculating backup size: {e}")
    return total_bytes
# replication_groups stored in SQLite now

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user_data = database.get_user_by_username(username)
        if user_data and check_password_hash(user_data['password_hash'], password):
            user = User(user_data['id'], user_data['username'], user_data['role'])
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

def get_client_by_id(is_source, id):
    if is_source:
        conf = settings.get_source_by_id(id)
    else:
        conf = settings.get_destination_by_id(id)
    
    if conf:
        role = 'source' if is_source else 'destination'
        return AvamarClient(conf['host'], conf['user'], conf['password'], role=role)
    return None


def check_host_conflict(host, is_source):
    """Check if host already exists in the opposite list."""
    if is_source:
        # Check if host exists in destinations
        for d in settings.get_destinations():
            if d['host'] == host:
                return True, f"Host {host} is already configured as a Destination"
    else:
        # Check if host exists in sources
        for s in settings.get_sources():
            if s['host'] == host:
                return True, f"Host {host} is already configured as a Source"
    return False, None

@app.route('/api/jobs/<group_name>/client/<client_name>/backups', methods=['GET'])
@login_required
def get_migration_backups(group_name, client_name):
    # 1. Find the job by group_name
    jobs = database.get_all_migrations()
    job = next((j for j in jobs if j['group_name'] == group_name), None)
    if not job:
        return jsonify({'error': 'Job not found'}), 404

    # 2. Get Source and Dest Clients
    settings_s = settings.get_sources()
    settings_d = settings.get_destinations()

    def get_avamar(is_source, host):
        candidates = settings_s if is_source else settings_d
        conf = next((x for x in candidates if x['host'] == host), None)
        if conf:
            try:
                pw = settings._decrypt(conf['password'])
                role = 'source' if is_source else 'destination'
                ac = AvamarClient(conf['host'], conf['user'], pw, role=role)
                if ac._authenticate():
                    return ac
            except:
                pass
        return None

    src_sys = get_avamar(True, job['source_system'])
    dst_sys = get_avamar(False, job['destination_system'])

    if not src_sys:
        return jsonify({'error': 'Source System Offline'}), 500
    if not dst_sys:
        return jsonify({'error': 'Destination System Offline'}), 500

    results = {
        'source': [],
        'destination': [],
        'aligned_backups': []
    }

    # 3. Fetch Source Backups
    # Need to find the source CID again or pass it?
    # We can query database for cid if we stored it? Yes we did.
    clients = database.get_clients_for_job(group_name)
    db_client = next((c for c in clients if c['client_name'] == client_name), None)
    
    if not db_client:
         return jsonify({'error': 'Client not found in job'}), 404
         
    try:
        s_backups = src_sys.get_client_backups(db_client['client_cid'])
        results['source'] = s_backups
    except Exception as e:
        return jsonify({'error': f"Source Read Error: {e}"}), 500

    # 4. Fetch Dest Backups
    try:
        # Resolve dest CID (Reuse logic or rely on stored domain)
        dest_cid = None
        
        # Fast path: stored domain
        if db_client['dest_client_domain']:
             # We need to find client ID from domain + name
             # AvamarClient API doesn't have get_client_by_fqdn? 
             # Let's search by name in that domain
             found = dst_sys.get_client_by_name(client_name, domain=db_client['dest_client_domain'])
             if found: dest_cid = found['id']
             
        if not dest_cid:
            # Fallback Search
            found = dst_sys.get_client_by_name(client_name, domain='/')
            if not found:
                 # Fuzzy logic again
                 rep_clients = dst_sys.get_clients(domain='/REPLICATE')
                 target_name = client_name.lower()
                 match = next((rc for rc in rep_clients if target_name in rc.get('name','').lower() or target_name in rc.get('domainFqdn','').lower()), None)
                 if match: dest_cid = match['id']
            else:
                 dest_cid = found['id']
                 
        if dest_cid:
            d_backups = dst_sys.get_client_backups(dest_cid)
            results['destination'] = d_backups
            
    except Exception as e:
        # Destination failure shouldn't block seeing source backups, but we can't align
        print(f"Dest Read Error: {e}") 

    # 5. Alignment Logic
    # We want a list of rows: { source_backup: Obj|None, dest_backup: Obj|None, status: 'Synced'|'Missing'|'Extra' }
    
    s_map = {b.get('creationTime') or b.get('labelNumber'): b for b in results['source']}
    d_map = {b.get('creationTime') or b.get('labelNumber'): b for b in results['destination']}
    
    all_keys = set(s_map.keys()) | set(d_map.keys())
    
    aligned = []
    for k in all_keys:
        s_obj = s_map.get(k)
        d_obj = d_map.get(k)
        
        status = 'UNKNOWN'
        if s_obj and d_obj:
            status = 'SYNCED'
        elif s_obj and not d_obj:
            status = 'MISSING_ON_DEST'
        elif not s_obj and d_obj:
            status = 'EXTRA_ON_DEST'
            
        # Common fields for sorting
        sort_date = (s_obj or d_obj).get('date')
        
        aligned.append({
            'key': k,
            'source': s_obj,
            'dest': d_obj,
            'status': status,
            'sort_date': sort_date
        })
        
    # Sort by date descending
    aligned.sort(key=lambda x: x['sort_date'] or '', reverse=True)
    results['aligned_backups'] = aligned

    return jsonify(results)


@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/api/settings/sources', methods=['GET', 'POST'])
@login_required
def handle_sources():
    if request.method == 'POST':
        if current_user.role != 'admin':
            return jsonify({'error': 'Admin privileges required'}), 403
        data = request.json
        host = data.get('host')
        
        # Check for conflict with destinations
        conflict, msg = check_host_conflict(host, is_source=True)
        if conflict:
            return jsonify({'error': msg}), 400
            
        database.log_audit_event(current_user.username, 'source_added', f"Avamar Source {host} added")
        settings.add_source(data)
        return jsonify({'status': 'ok'})
    else:
        sources = settings.get_sources()
        return jsonify(strip_passwords(sources))

@app.route('/api/settings/destinations', methods=['GET', 'POST'])
@login_required
def handle_destinations():
    if request.method == 'POST':
        if current_user.role != 'admin':
            return jsonify({'error': 'Admin privileges required'}), 403
        data = request.json
        host = data.get('host')
        
        # Check for conflict with sources
        conflict, msg = check_host_conflict(host, is_source=False)
        if conflict:
            return jsonify({'error': msg}), 400
            
        database.log_audit_event(current_user.username, 'dest_added', f"Avamar Destination {host} added")
        settings.add_destination(data)
        return jsonify({'status': 'ok'})
    else:
        dests = settings.get_destinations()
        return jsonify(strip_passwords(dests))

@app.route('/api/settings/sources/<id>', methods=['DELETE'])
@admin_required
def delete_source(id):
    src = settings.get_source_by_id(id)
    host = src['host'] if src else 'Unknown'
    settings.delete_source(id)
    database.log_audit_event(current_user.username, 'source_removed', f"Avamar Source {host} removed from configuration")
    return jsonify({'status': 'ok'})

@admin_required
@app.route('/api/settings/destinations/<id>', methods=['DELETE'])
def delete_dest(id):
    dst = settings.get_destination_by_id(id)
    host = dst['host'] if dst else 'Unknown'
    settings.delete_destination(id)
    database.log_audit_event(current_user.username, 'dest_removed', f"Avamar Destination {host} removed from configuration")
    return jsonify({'status': 'ok'})

@admin_required
@app.route('/api/settings/reset', methods=['POST'])
def reset_settings():
    password = request.json.get('password')
    if not password:
         return jsonify({'error': 'Password required'}), 400
         
    # Verify Admin Password
    user_data = database.get_user_by_id(current_user.id)
    if not user_data or not check_password_hash(user_data['password_hash'], password):
        # Allow checking against verify default admin if current user is admin?
        # Actually current_user IS admin strictly due to @admin_required decorator
        return jsonify({'error': 'Invalid password'}), 403

    # Reset
    try:
        # 1. Reset DB
        database.reset_configuration()
        # 2. Reset Config File
        settings.reset_defaults()
        
        # 3. Log (fresh log)
        database.log_audit_event(current_user.username, 'system_reset', "System configuration reset to defaults")
        
        return jsonify({'status': 'ok'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@login_required
@app.route('/api/system/health', methods=['GET'])
def system_health():
    # Use IDs from query or cookies.
    # User requested storing selection in cookie.
    
    source_id = request.args.get('source_id') or request.cookies.get('source_id')
    dest_id = request.args.get('dest_id') or request.cookies.get('dest_id')
    
    health = {
        "source": {"host": "None Selected", "status": "Unknown"},
        "destination": {"host": "None Selected", "status": "Unknown"}
    }
    
    if source_id:
        client = get_client_by_id(True, source_id)
        if client:
            health["source"]["host"] = settings.get_source_by_id(source_id)['host']
            try:
                s_status = client.get_system_status()
                health["source"]["status"] = "Online" if s_status else "Error"
            except Exception as e:
                health["source"]["status"] = f"Error: {str(e)}"
        else:
             health["source"]["status"] = "Invalid ID"

    if dest_id:
        client = get_client_by_id(False, dest_id)
        if client:
            health["destination"]["host"] = settings.get_destination_by_id(dest_id)['host']
            try:
                d_status = client.get_system_status()
                health["destination"]["status"] = "Online" if d_status else "Error"
            except Exception as e:
                health["destination"]["status"] = f"Error: {str(e)}"
        else:
            health["destination"]["status"] = "Invalid ID"
        
    return jsonify(health)


@app.route('/api/system/capacity', methods=['GET'])
@login_required
def system_capacity():
    """Get storage capacity information for source and destination systems."""
    source_id = request.args.get('source_id') or request.cookies.get('source_id')
    dest_id = request.args.get('dest_id') or request.cookies.get('dest_id')
    
    def format_gb(bytes_val):
        """Convert bytes to GB with 2 decimal places."""
        if not bytes_val:
            return None
        return round(bytes_val / (1024**3), 2)
    
    capacity = {
        "source": {"total_gb": None, "used_gb": None, "free_gb": None, "usage_percent": None},
        "destination": {"total_gb": None, "used_gb": None, "free_gb": None, "usage_percent": None}
    }
    
    if source_id:
        client = get_client_by_id(True, source_id)
        if client:
            try:
                storage = client.get_storage_info()
                if storage:
                    total = storage.get('totalCapacity', 0)
                    used = storage.get('usedCapacity', 0)
                    capacity["source"]["total_gb"] = format_gb(total)
                    capacity["source"]["used_gb"] = format_gb(used)
                    capacity["source"]["free_gb"] = format_gb(total - used) if total and used else None
                    if total:
                        capacity["source"]["usage_percent"] = round((used / total) * 100, 1)
            except Exception as e:
                app.logger.warning(f"Failed to get source capacity: {e}")
    
    if dest_id:
        client = get_client_by_id(False, dest_id)
        if client:
            try:
                storage = client.get_storage_info()
                if storage:
                    total = storage.get('totalCapacity', 0)
                    used = storage.get('usedCapacity', 0)
                    capacity["destination"]["total_gb"] = format_gb(total)
                    capacity["destination"]["used_gb"] = format_gb(used)
                    capacity["destination"]["free_gb"] = format_gb(total - used) if total and used else None
                    if total:
                        capacity["destination"]["usage_percent"] = round((used / total) * 100, 1)
            except Exception as e:
                app.logger.warning(f"Failed to get destination capacity: {e}")
    
    return jsonify(capacity)


@app.route('/api/scan', methods=['POST'])
@admin_required
def scan_clients():
    global candidates_cache
    
    try:
        # Get source_id from JSON body, Query Args, or Cookies
        data = request.get_json(silent=True) or {}
        source_id = data.get('source_id') or request.args.get('source_id') or request.cookies.get('source_id')
        
        if not source_id:
             return jsonify({'error': 'No Source System Selected'}), 400
             
        client = get_client_by_id(True, source_id)
        if not client:
            return jsonify({'error': 'Invalid Source ID'}), 400

        # 1. Get all clients
        # 1. Get all clients
        all_clients = client.get_clients()
        candidates = []
        
        # 2. Filter logic
        for c in all_clients:
            # Check if inactive (restoreOnly=True)
            # User requirement: List all, highlight inactive/recommended
            is_inactive = c.get('restoreOnly', False)
            
            # Filter internal clients
            if '/MC_SYSTEM' in c['name'] or '/MC_SYSTEM' in c['domainFqdn']:
                continue

            has_backups = c.get('totalBackups', 0) > 0
            
            # Fetch active backup groups
            active_groups_count = 0
            group_names = []
            try:
                groups = client.get_client_groups(c['id'])
                # Filter groups: Must be Enabled AND "Backup" type (Not Replication)
                # Backup types are typically REGULAR, VMWARE. We exclude explicit REPLICATION types.
                # User identified 'REPLICATE' as the specific type value for replication groups.
                filtered_groups = [g for g in groups if g.get('enabled') and 'REPLICATE' not in g.get('type', '').upper()]
                active_groups_count = len(filtered_groups)
                group_names = [g['name'] for g in filtered_groups]
            except Exception as e:
                print(f"Error fetching groups for {c['name']}: {e}")

            status_label = "Active"
            if is_inactive:
                status_label = "Inactive (Restore Only)"

            # We can use this flag in UI to highlight or sort
            is_candidate = is_inactive and has_backups

            candidates.append({
                'id': c['id'],
                'name': c['name'],
                'domain': c['domainFqdn'],
                'totalBackups': c['totalBackups'],
                'lastBackup': c.get('lastBackupTime'),
                'activeGroups': active_groups_count,
                'groupNames': group_names,
                'status': status_label,
                'is_candidate': is_candidate
            })
        
        # Sort: Candidates first, then by name
        candidates.sort(key=lambda x: (not x['is_candidate'], x['name']))
        
        candidates_cache = candidates
        return jsonify({'count': len(candidates), 'candidates': candidates})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/candidates', methods=['GET'])
@admin_required
def get_candidates():
    return jsonify(candidates_cache)

@admin_required
@app.route('/api/destinations', methods=['GET'])
def get_destinations():
    source_id = request.args.get('source_id') or request.cookies.get('source_id')
    if not source_id: return jsonify({'error': 'No Source Selected'}), 400
    
    client = get_client_by_id(True, source_id)
    try:
        dests = client.get_replication_destinations()
        return jsonify(dests)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@admin_required
@app.route('/api/replicate', methods=['POST'])
def create_replication():
    data = request.get_json(silent=True) or {}
    
    source_id = data.get('source_id') or request.cookies.get('source_id')
    if not source_id: return jsonify({'error': 'No Source Selected'}), 400
    
    client = get_client_by_id(True, source_id)
    if not client:
        return jsonify({'error': 'Source Client not found. Please check settings.'}), 400
    
    # ... rest of logic
    
    # Step 1: Handle Destination
    # The ID passed here is from our local 'settings_manager' (dest_id) which corresponds to an entry in config.json
    # We must see if this destination exists on the ACTUAL Avamar Source system.

    dest_id = data.get('destinationId')
    dest_config = settings.get_destination_by_id(dest_id) # Our local config
    if not dest_config:
        return jsonify({'error': 'Local Destination Config not found'}), 400
        
    dest_ip = dest_config['host']
    dest_user = dest_config['user']
    dest_pw = dest_config['password'] # We need to decrypt this if SettingsManager doesn't
    # SettingsManager returns plain dict, assuming it handles decryption: 
    # Let's check settings_manager.py... 
    # Actually SettingsManager decrypts on get_* methods.
    
    # Check if Destination Exists on Source Avamar
    real_dest_id = None
    try:
        existing_dests = client.get_replication_destinations()
        # Ensure it's a list even if API wraps it or returns single object
        if isinstance(existing_dests, dict): existing_dests = [existing_dests]
            
        for d in existing_dests:
            # Match by host/IP or name? Avamar stores 'host' usually.
            # d is expected to be a dict, but error implies it's not somehow?
            # Or get_replication_destinations returned something unexpected
            if not isinstance(d, dict): continue
            
            if d.get('host') == dest_ip or d.get('name') == dest_config['name']:
                real_dest_id = d.get('id')
                break
        
        # If not found, Create it!
        if not real_dest_id:
            print(f"Destination {dest_ip} not found on source. Creating...")
            resp = client.create_replication_destination(
                dest_config['name'], 
                dest_ip, 
                dest_user, 
                dest_pw
            )
            if resp.status_code >= 300:
                return jsonify({'error': f"Failed to create replication destination: {resp.text}"}), 400
            
            # Use the ID from the creation response
            # Response might be the object or just ID 
            # (Assuming Avamar returns created object or 201 with Location)
            # Standard Avamar tends to return the object.
            new_d = resp.json()
            real_dest_id = new_d.get('id')
            if not real_dest_id:
                 # Fetch list again as fallback
                 existing_dests = client.get_replication_destinations()
                 for d in existing_dests:
                    if d.get('host') == dest_ip:
                        real_dest_id = d['id']
                        break
    except Exception as e:
        return jsonify({'error': f"Error validating destination: {str(e)}"}), 500

    if not real_dest_id:
        return jsonify({'error': 'Could not determine Avamar Destination ID (Creation failed?)'}), 500

    cids = data.get('candidates', [])
    if not cids:
        return jsonify({'error': 'No candidates selected'}), 400
    
    # Resolve Client Names from Cache
    client_details = []
    for cid in cids:
        match = next((c for c in candidates_cache if c.get('id') == cid), None)
        if match:
             client_details.append(match)
        else:
             # Try to fetch from Avamar if not in cache (e.g. after server restart)
             try:
                 found = client.get_client_by_id(cid)
                 if found:
                     client_details.append({
                        'id': found.get('id'),
                        'name': found.get('name'),
                        'domain': found.get('domainFqdn') or found.get('domain'),
                        'totalBackups': found.get('totalBackups', 0)
                     })
                 else:
                     client_details.append({'id': cid, 'name': 'Unknown', 'domain': 'Unknown'})
             except:
                 client_details.append({'id': cid, 'name': 'Unknown', 'domain': 'Unknown'})

    # Use Incident Number for unique name
    incident_num = data.get('incidentNumber', '').strip()
    if not incident_num:
         return jsonify({'error': 'Incident/Change Number is required'}), 400
         
    safe_suffix = re.sub(r'[^a-zA-Z0-9_\-]', '', incident_num)
    if not safe_suffix:
         return jsonify({'error': 'Invalid characters in Incident Number'}), 400
         
    group_name = f"Migration_{safe_suffix}"
    
    try:
        # Create Group using REAL Avamar ID
        resp = client.create_replication_group(group_name, cids, real_dest_id)
        if resp.status_code >= 300:
             return jsonify({'error': resp.text}), 400
             
        group_data = resp.json()
        
        # Log Audit Event
        database.log_audit_event(
            current_user.username, 
            'create_replication_group', 
            f"Created group {group_name} with {len(cids)} clients. Target: {dest_config['host']}", 
            incident_num
        )
        
        # Store for tracking
        database.log_migration_job(
            group_name, 
            settings.get_source_by_id(source_id)['host'],
            dest_config['host'],
            client_details
        )
        
        return jsonify({'message': 'Group Created', 'group': group_data})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/replication/status', methods=['GET'])
def replication_status():
    jobs = database.get_all_migrations()
    print(f"DEBUG: replication_status found {len(jobs)} jobs in DB")
    
    # We want live status for the replication group
    clients = {} # host -> client_obj
    
    def get_cached_client(host):
        if host in clients: return clients[host]
        
        # Check settings
        # settings.get_sources() returns the list of dicts with encrypted passwords
        for s in settings.get_sources():
            if s['host'] == host:
                try:
                    pw = settings._decrypt(s['password'])
                    cl = AvamarClient(host, s['user'], pw, role='source')
                    cl._authenticate()
                    clients[host] = cl
                    return cl
                except Exception as e:
                    print(f"Auth failed for {host}: {e}")
                    return None
        return None

    for job in jobs:
        # Aggregation from DB
        db_clients = database.get_clients_for_job(job['group_name'])
        total_clients = len(db_clients)
        synced_count = sum(1 for c in db_clients if c['status'] == 'SYNCED')
        in_policy_count = sum(1 for c in db_clients if c.get('in_policy_groups', 1) == 1)
        
        # 1. Progress Calculation
        percent = 0
        if total_clients > 0:
            percent = int((synced_count / total_clients) * 100)
        job['percent_complete'] = percent
        
        # 2. Clients Removed Flag
        job['all_clients_removed'] = (in_policy_count == 0)
        
        # 3. Avamar Status Check
        host = job['source_system']
        client = get_cached_client(host)
        
        if client:
            try:
                # Get live status from Avamar
                details = client.get_replication_group_details_full(job['group_name'])
                status = details.get('status', 'Unknown')
                job['status'] = status
                job['last_activity'] = details
            except Exception as e:
                # If error, indicate it but keep the job entry
                job['status'] = f"Check Failed: {str(e)}"
        else:
             if job['status'] == 'ACTIVE': 
                 job['status'] = "Active (Source Unreachable)"
        
        # 4. Final Status Logic
        # - If Avamar is running (Active/Replicating), override everything with that activity
        # - If Avamar is idle/failed/completed, use the Client Sync Status
        
        avamar_status_text = str(job.get('status', 'Unknown'))

        # Check if Avamar is "busy"
        is_running = avamar_status_text.lower() in ['active', 'running', 'queued']
        
        final_status = avamar_status_text # Default fallback
        if is_running:
            final_status = f"{avamar_status_text} ({percent}%)"
        else:
            # Not running, check sync
            if synced_count == total_clients and total_clients > 0:
                final_status = "UP TO DATE"
            elif synced_count < total_clients:
                 # Check if failed or just not run
                 if avamar_status_text in ['Failed', 'Completed with Errors']:
                     final_status = "Failed / Incomplete"
                 else:
                     final_status = "Sync Pending"
        
        # Override object status
        job['status'] = final_status
        job['in_policy_count'] = in_policy_count # Helping frontend text
    
    return jsonify(jobs)

def perform_migration_check(limit_group_name=None):
    try:
        print("DEBUG: Starting perform_migration_check")
        jobs = database.get_all_migrations()
        
        if limit_group_name:
            jobs = [j for j in jobs if j['group_name'] == limit_group_name]

        # We need to map source/dest hosts to credentials
        sources_conf = settings.get_sources()
        dests_conf = settings.get_destinations()

    
        # Cache clients
        source_clients = {} # ip -> AvamarClient
        dest_clients = {}   # ip -> AvamarClient
        
        def get_client(is_source, host):
            cache = source_clients if is_source else dest_clients
            if host in cache: return cache[host]
            
            candidates = sources_conf if is_source else dests_conf
            # Match by host
            conf = next((x for x in candidates if x['host'] == host), None)
            if conf:
                try:
                    # Decrypt if needed (get_sources returns encrypted pw in 'password' field)
                    # settings.get_source_by_id decrypts it, but we have the raw list.
                    # Let's assume we need to decrypt.
                    pw = settings._decrypt(conf['password'])
                    role = 'source' if is_source else 'destination'
                    ac = AvamarClient(conf['host'], conf['user'], pw, role=role)
                    
                    # Test auth
                    # _authenticate now returns True or raises
                    if ac._authenticate():
                        cache[host] = ac
                        return ac
                except Exception as e:
                    print(f"Failed to connect to {host}: {e}")
            return None

        results = []

        for job in jobs:
            group_name = job['group_name']
            clients = database.get_clients_for_job(group_name)
            
            s_host = job['source_system']
            d_host = job['destination_system']
            
            src_sys = get_client(True, s_host)
            dst_sys = get_client(False, d_host)
            
            for c in clients:
                status_update = {}
                notes = []
                
                source_backups_list = []
                dest_backups_list = []
                
                # 1. Source Check
                if src_sys:
                    try:
                        # Check backups (Source)
                        backups = src_sys.get_client_backups(c['client_cid'])
                        if backups and isinstance(backups, list):
                            source_backups_list = backups
                            
                        current_s_count = len(source_backups_list)
                        status_update['source_count'] = current_s_count
                        
                        # Calculate Source Size
                        status_update['source_bytes'] = calculate_backup_size(source_backups_list)
                        
                        # Check Group Membership
                        groups = src_sys.get_client_groups(c['client_cid'])
                        in_pg = 1 # Default True
                        
                        if groups:
                            # Filter out Replication Groups & Default Group
                            # Robust check for REPLICATE type
                            backup_groups = [
                                g for g in groups 
                                if 'REPLICATE' not in g.get('type', '').upper() 
                                and g.get('name') != 'Default Group'
                            ]
                            
                            if backup_groups:
                                notes.append(f"In {len(backup_groups)} Backup groups")
                            else:
                                notes.append("No active policies")
                                in_pg = 0
                        else:
                            notes.append("No active policies")
                            in_pg = 0
                        
                        status_update['in_policy_groups'] = in_pg
                            
                    except Exception as e:
                        notes.append(f"Source Check Error: {str(e)}")
                        status_update['in_policy_groups'] = 1 # Assume worst on error
                
                # 2. Destination Check
                if dst_sys:
                    try:
                        # Check if client exists by name (Standard Search from Root)
                        found_client = dst_sys.get_client_by_name(c['client_name'], domain='/')
                        
                        # If not found, explicitly search the /REPLICATE domain tree.
                        # Standard recursion often treats /REPLICATE as a separate tree or requires explicit entry.
                        if not found_client:
                            try:
                                # Try exact match in /REPLICATE
                                found_client = dst_sys.get_client_by_name(c['client_name'], domain='/REPLICATE')
                                if found_client:
                                    pass
                                else:
                                    # Fallback: Loose match (case-insensitive) by fetching all clients in /REPLICATE
                                    # We check if client_name is part of the destination client's FQDN or name
                                    rep_clients = dst_sys.get_clients(domain='/REPLICATE')
                                    target_name = c['client_name'].lower()
                                    
                                    # Helper: Check mostly likely fields
                                    def is_match(rc):
                                        r_name = rc.get('name', '').lower()
                                        r_fqdn = rc.get('domainFqdn', '').lower() # e.g. /REPLICATE/domain/client
                                        # 1. Name Exact
                                        if r_name == target_name: return True
                                        # 2. Target in Name (substring)
                                        if target_name in r_name: return True
                                        # 3. Name in Target
                                        if r_name in target_name and len(r_name) > 3: return True
                                        # 4. Target in FQDN path
                                        if target_name in r_fqdn: return True
                                        return False

                                    match = next((rc for rc in rep_clients if is_match(rc)), None)
                                    if match:
                                        found_client = match
                                        notes.append("Found (Fuzzy Match) in /REPLICATE")
                            except Exception as ex:
                                # /REPLICATE domain might not exist if no replication has ever happened
                                print(f"Deep search error: {ex}")
                                pass
                        
                        if found_client:
                            # Use domainFqdn if available, otherwise domain. 
                            # The Avamar API 'clients' endpoint often returns 'domainFqdn' or just 'domain'.
                            # Our debug script confirms 'domainFqdn' is populated.
                            status_update['dest_domain'] = found_client.get('domainFqdn') or found_client.get('domain')
                            
                            d_backups = dst_sys.get_client_backups(found_client['id'])
                            if d_backups and isinstance(d_backups, list):
                                dest_backups_list = d_backups
                                
                            current_d_count = len(dest_backups_list)
                            status_update['dest_count'] = current_d_count

                            # Calculate Dest Size
                            status_update['dest_bytes'] = calculate_backup_size(dest_backups_list)

                        else:
                            status_update['dest_count'] = 0
                            status_update['dest_bytes'] = 0
                            notes.append("Not found on Dest")
                            
                    except Exception as e:
                        notes.append(f"Dest Check Error: {str(e)}")

                # 3. Determine Status
                # Use new values if available, else keep old
                s_count = status_update.get('source_count', c.get('source_backup_count') or 0)
                d_count = status_update.get('dest_count', c.get('dest_backup_count') or 0)
                
                s_bytes = status_update.get('source_bytes', c.get('source_total_bytes') or 0)
                d_bytes = status_update.get('dest_bytes', c.get('dest_total_bytes') or 0)
                
                # Compare Backups for Precise Sync Status
                # We use 'creationTime' if available, otherwise 'date' string ?? No, creationTime is robust.
                # If source is empty, and dest is whatever -> Synced?
                
                new_status = 'PENDING'
                
                if not src_sys:
                    new_status = 'SOURCE_OFFLINE'
                elif not dst_sys:
                    new_status = 'DEST_OFFLINE'
                elif s_count == 0:
                     # No backups on source. If client exists on Dest, considered Synced (nothing to move)
                     new_status = 'SYNCED'
                else:
                    # Compare IDs
                    # Helper to get ID set
                    def get_backup_ids(bk_list):
                        ids = set()
                        for b in bk_list:
                            # Use creationTime as unique identifier for backup contents
                            # 'date' is string, 'creationTime' is long timestamp
                            if b.get('creationTime'):
                                ids.add(b.get('creationTime'))
                            elif b.get('labelNumber'):
                                # Fallback (though labelNumber might differ if conflict, usually stable in replication)
                                ids.add(b.get('labelNumber'))
                        return ids
                    
                    s_ids = get_backup_ids(source_backups_list)
                    d_ids = get_backup_ids(dest_backups_list)
                    
                    # Logic: "The exact Backups that exist on Source, must live on Destination"
                    # missing_on_dest = S_ids - D_ids
                    missing_on_dest = s_ids - d_ids
                    
                    if not missing_on_dest:
                        new_status = 'SYNCED'
                    elif len(missing_on_dest) == len(s_ids):
                         # All missing
                         new_status = 'UNSYNCED'
                    else:
                         # Some missing
                         new_status = 'SYNCING'
                         # Add note about how many missing
                         notes.append(f"Missing {len(missing_on_dest)}/{len(s_ids)} backups")
                
                final_notes = "; ".join(notes)
                
                database.update_client_status(
                    c['id'], 
                    source_count=s_count,
                    dest_count=d_count,
                    source_bytes=s_bytes,
                    dest_bytes=d_bytes,
                    status=new_status,
                    notes=final_notes,
                    dest_domain=status_update.get('dest_domain'),
                    in_policy_groups=status_update.get('in_policy_groups')
                )
                
                results.append({
                    'client': c['client_name'],
                    'status': new_status,
                    's_count': s_count,
                    'd_count': d_count
                })
        print("DEBUG: perform_migration_check completed successfully")
        return results
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"CRITICAL ERROR in perform_migration_check: {e}")
        return []

@app.route('/api/migration/check', methods=['POST'])
def check_migration_status():
    results = perform_migration_check()
    return jsonify({'message': 'Check Complete', 'results': results})

@app.route('/api/jobs/<group_name>', methods=['GET'])
def get_job_details(group_name):
    try:
        # FORCE Update for this job
        perform_migration_check(limit_group_name=group_name)
        
        clients = database.get_clients_for_job(group_name)
        
        # Also fetch Activity Details (Start/End times)
        activity_info = {}
        
        all_jobs = database.get_all_migrations()
        job_record = next((j for j in all_jobs if j['group_name'] == group_name), None)
        
        if job_record:
            host = job_record['source_system']
            client = get_client_for_host(host, is_source=True)
            
            if client:
                 activity_info = client.get_replication_group_details_full(group_name)

        return jsonify({'clients': clients, 'activity': activity_info})
    except Exception as e:
        print(f"Error in get_job_details: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/jobs/<group_name>', methods=['DELETE'])
@admin_required
def delete_job(group_name):
    try:
        data = request.json or {}
        remove_clients = data.get('remove_clients', False)
        incident_ref = data.get('incident_number', None)
        
        if not incident_ref:
            return jsonify({'error': 'Incident/Change Number is required for deletion.'}), 400

        # 1. Start Logging
        database.log_audit_event(current_user.username, 'delete_migration_job', f"Started deletion of job {group_name}. Remove Clients: {remove_clients}", incident_ref)

        # 2. Get Job Details from DB
        all_jobs = database.get_all_migrations()
        job_record = next((j for j in all_jobs if j['group_name'] == group_name), None)
        
        if not job_record:
            return jsonify({'error': 'Job not found in database'}), 404
            
        group_id_in_db = job_record['id']

        # 3. Connect to Source
        host = job_record['source_system']
        client = get_client_for_host(host, is_source=True)
        
        if not client:
             return jsonify({'error': 'Could not connect to source system to perform deletion'}), 500

        # 4. Remove Clients if requested
        if remove_clients:
            job_clients = database.get_clients_for_job(group_id_in_db)
            for c in job_clients:
                try:
                    # Assuming we saved the 'domain' in the database (client_domain)
                    # We might need the CID. The database has client_cid.
                    cid = c.get('client_cid')
                    domain = c.get('client_domain')
                    if cid:
                         client.delete_client(cid, domain)
                         database.log_audit_event(current_user.username, 'delete_client', f"Deleted client {c['client_name']} ({cid}) from source", incident_ref)
                except Exception as e:
                     database.log_audit_event(current_user.username, 'delete_client_error', f"Failed to delete client {c['client_name']}: {str(e)}", incident_ref)

        # 5. Delete Replication Group on Avamar
        try:
            # We need the Group ID, not the Name, for the API call.
            # Fetch all groups and find the one with matching name.
            groups = client.get_replication_groups()
            target_group = next((g for g in groups if g.get('name') == group_name), None)
            
            if target_group:
                resp = client.delete_replication_group(target_group['id'])
                if resp.status_code >= 300:
                     return jsonify({'error': f"Failed to delete replication group: {resp.text}"}), 500
                
                database.log_audit_event(current_user.username, 'delete_replication_group', f"Deleted replication group {group_name} ({target_group['id']}) from Avamar", incident_ref)
            else:
                # Group might have been deleted manually or doesn't exist. Log warning but proceed to clear local DB.
                database.log_audit_event(current_user.username, 'delete_replication_group_skip', f"Replication group {group_name} not found on source system. Continuing cleanup.", incident_ref)

        except Exception as e:
             return jsonify({'error': f"Failed to delete replication group on Avamar: {str(e)}"}), 500

        # 6. Delete from Local Database
        database.delete_migration_job(group_id_in_db)
        database.log_audit_event(current_user.username, 'job_cleanup', f"Removed job {group_name} from local tracking", incident_ref)
        
        return jsonify({'status': 'deleted'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/jobs/<group_name>/run', methods=['POST'])
def run_job(group_name):
    # Find job to get source host
    all_jobs = database.get_all_migrations()
    job_record = next((j for j in all_jobs if j['group_name'] == group_name), None)
    
    if not job_record:
        return jsonify({'error': 'Job not found'}), 404
        
    host = job_record['source_system']
    
    # Authenticate
    client = get_client_for_host(host, is_source=True)

    if not client:
        return jsonify({'error': 'Could not connect to source system'}), 500

    # Find Group ID
    groups = client.get_replication_groups()
    target = next((g for g in groups if g.get('name') == group_name), None)
    
    if not target:
        return jsonify({'error': 'Replication Group not found on Avamar'}), 404
        
    # Run it
    try:
        resp = client.run_replication_group(target['id'])
        if resp.status_code == 200 or resp.status_code == 204:
             return jsonify({'status': 'initiated'})
        return jsonify({'error': f"Avamar API Error: {resp.status_code} {resp.text}"}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/jobs/<group_name>/cancel', methods=['POST'])
def cancel_job(group_name):
    all_jobs = database.get_all_migrations()
    job_record = next((j for j in all_jobs if j['group_name'] == group_name), None)
    
    if not job_record:
        return jsonify({'error': 'Job not found'}), 404
        
    host = job_record['source_system']
    
    # Authenticate
    client = get_client_for_host(host, is_source=True)
            
    if not client:
        return jsonify({'error': 'Could not authenticate to Source'}), 500

    try:
        result = client.stop_replication_activity(group_name)
        if 'error' in result:
             return jsonify(result), 400
        
        database.log_audit_event(current_user.username, 'job_cancel', f"Replication Job {group_name} cancelled")
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/report')
@login_required
def print_report():
    migrations = database.get_all_migrations()
    jobs_data = []
    
    # Process each migration job
    for m in migrations:
        clients = database.get_clients_for_job(m['id'])
        
        # Calculate stats for the header
        synced_count = sum(1 for c in clients if c['status'] == 'SYNCED')
        pending_count = sum(1 for c in clients if c['status'] != 'SYNCED')
        total = len(clients) if len(clients) > 0 else 1
        percent = int((synced_count / total) * 100)

        job_entry = {
            'group_name': m['group_name'],
            'created_at': m['created_at'],
            'client_details': clients,
            'stats': {
                'synced': synced_count,
                'pending': pending_count
            },
            'percent_complete': percent
        }
        jobs_data.append(job_entry)
        
    return render_template('report.html', 
                          generated_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                          sources=settings.get_sources(),
                          destinations=settings.get_destinations(),
                          jobs=jobs_data)

@app.route('/audit')
@admin_required
def audit_log():
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    page_size = request.args.get('page_size', 10, type=int)
    if page_size not in [10, 100]:
        page_size = 10
    
    # Get sorting parameters
    sort_column = request.args.get('sort', 'timestamp')
    sort_order = request.args.get('order', 'DESC')
    
    # Get search parameter
    search = request.args.get('search', '').strip() or None
    
    # Get show history parameter
    show_history = request.args.get('show_history', 'false').lower() == 'true'
    
    # Calculate offset
    offset = (page - 1) * page_size
    
    # Get logs with pagination, sorting and search
    result = database.get_audit_logs(
        limit=page_size,
        offset=offset,
        include_archived=show_history,
        sort_column=sort_column,
        sort_order=sort_order,
        search=search
    )
    
    # Calculate pagination info
    total_pages = (result['total_count'] + page_size - 1) // page_size
    
    return render_template('audit.html', 
                          logs=result['logs'],
                          show_history=show_history,
                          page=page,
                          page_size=page_size,
                          total_count=result['total_count'],
                          total_pages=total_pages,
                          sort_column=sort_column,
                          sort_order=sort_order,
                          search=search or '')


@app.route('/api/audit/clear', methods=['POST'])
@admin_required
def clear_audit_logs():
    """Archive (soft delete) all visible audit logs."""
    try:
        archived_count = database.archive_audit_logs()
        # Log the archive action itself (this will be the only visible log after clearing)
        database.log_audit_event(
            current_user.username,
            'audit_logs_cleared',
            f"Archived {archived_count} audit log entries. Use 'Show history' to view archived logs."
        )
        return jsonify({'status': 'ok', 'archived_count': archived_count})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    database.init_db()
    app.run(debug=True, port=5000)
