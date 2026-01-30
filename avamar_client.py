import requests
import urllib3
import json
import base64
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class AvamarClient:
    def __init__(self, host, username, password):
        self.host = host # save host for raw url construction
        self.base_url = f"https://{host}" # Changed to root, endpoints will add /api
        self.username = username
        self.password = password
        self.token = None
        self.session = requests.Session()
        self.session.verify = False
        
        # Static Client Identity similar to the reference project
        self.client_id = "AvamarMigrator"
        self.client_secret = "AvamarMigratorSecret123!"

    def get_system_status(self):
        """Checks if the system is reachable and authenticated."""
        try:
            # If we don't have a token, this will try to get one.
            # If we do, we might want to verify it's valid by making a cheap call.
            if not self.token:
                self._authenticate()
            
            # Make a cheap call to verify API responsiveness
            # /v1/domains?recursive=false is usually fast
            resp = self._request('GET', '/v1/domains', params={'domain': '/', 'recursive': 'false'})
            if resp.status_code == 200:
                return True
            return False
        except Exception as e:
            print(f"System status check failed: {e}")
            raise e

    def _authenticate(self):
        print(f"Starting Authentication logic for {self.host}...")
        
        # Try to get token first (assuming client might already exist)
        token = self._get_access_token()
        if token:
            self.token = token
            print("Token retrieved successfully.")
            return True

        # If failed, try to register the client
        print("Token retrieval failed. Attempting to register OAuth client...")
        if self._create_oauth_client():
            # Retry token
            token = self._get_access_token()
            if token:
                self.token = token
                print("Token retrieved successfully after registration.")
                return True
        
        raise Exception("Authentication Failed: Could not get token or register client.")

    def _create_oauth_client(self):
        url = f"{self.base_url}/api/v1/oauth2/clients"
        
        # Basic Auth with User Credentials
        auth_string = f"{self.username}:{self.password}"
        auth_header = base64.b64encode(auth_string.encode()).decode()
        
        headers = {
            "Authorization": f"Basic {auth_header}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "clientName": self.client_id,
            "clientId": self.client_id,
            "clientSecret": self.client_secret,
            "accessTokenValiditySeconds": "1800",
            "authorizedGrantTypes": ["password"],
            "autoApproveScopes": ["all"],
            "redirectUris": ["https://localhost/callback"],
            "refreshTokenValiditySeconds": "43200",
            "scopes": ["read", "write"]
        }
        
        try:
            resp = self.session.post(url, json=payload, headers=headers)
            if resp.status_code in [200, 201]:
                return True
            if resp.status_code == 400:
                print("Client likely already exists.")
                return True
            
            # User request: Treat 401 as indication that client exists/reusable 
            # (e.g. if we lack permission to create but it's there)
            if resp.status_code == 401:
                print("Client registration returned 401. Assuming client exists and proceeding.")
                return True
            
            print(f"Failed to create client: {resp.status_code} {resp.text}")
            return False
        except Exception as e:
            print(f"Exception creating client: {e}")
            return False

    def _get_access_token(self):
        url = f"{self.base_url}/api/oauth/token"
        
        # Basic Auth with Client Credentials
        auth_string = f"{self.client_id}:{self.client_secret}"
        auth_header = base64.b64encode(auth_string.encode()).decode()
        
        headers = {
            "Authorization": f"Basic {auth_header}",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        data = {
            "grant_type": "password",
            "username": self.username,
            "password": self.password,
            "scope": "write"
        }
        
        try:
            resp = self.session.post(url, data=data, headers=headers)
            if resp.status_code == 200:
                return resp.json().get('access_token')
            print(f"Failed to get token: {resp.status_code} {resp.text}")
            return None
        except Exception as e:
            print(f"Exception getting token: {e}")
            return None

    def _request(self, method, endpoint, params=None, json_data=None):
        if not self.token:
            self._authenticate()

        # Endpoint passed usually starts with /v1/... but base_url is just host
        # We need to ensure we hit /api/v1 OR whatever the caller expects.
        # Original code had self.base_url = .../api
        # Reference project uses URLs like {base_url}/api/v1/...
        
        # Let's standardize: 
        # If endpoint starts with /, append to base_url + /api
        # But wait, reference used /api/v1/oauth2/clients but /api/oauth/token
        # It seems the /api prefix is common.
        
        # The methods below (get_clients etc) use /v1/clients.
        # So we should construct: https://host/api/v1/clients
        
        url = f"{self.base_url}/api{endpoint}"
        
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': f"Bearer {self.token}"
        }
        
        response = self.session.request(method, url, params=params, json=json_data, headers=headers)
        
        if response.status_code == 401:
            print("Token expired or invalid, re-authenticating...")
            try:
                self._authenticate()
                headers['Authorization'] = f"Bearer {self.token}"
                response = self.session.request(method, url, params=params, json=json_data, headers=headers)
            except:
                pass 
                
        return response

    def get_clients(self, domain='/'):
        clients = []
        page = 0
        while True:
            params = {
                'page': page, 
                'size': 100,
                'domain': domain,
                'recursive': 'true'
            }
            resp = self._request('GET', '/v1/clients', params=params)
            if resp.status_code != 200:
                print(f"Error fetching clients: {resp.text}")
                break
                
            data = resp.json()
            # The schema showed Page«Client» but didn't explicitly show 'content'. 
            # Spring Hateoas/Data usually puts items in 'content' or 'clients'.
            # Based on common Avamar API, it might be 'content'.
            
            # Let's inspect the first response structure in the app logic or assume 'content'
            current_batch = data.get('content', [])
            if not current_batch:
                break
                
            clients.extend(current_batch)
            if data.get('last', True):
                break
            page += 1
            
        return clients

    def get_client_by_name(self, name, domain='/'):
        # Try to find specific client using filter
        params = {
            'domain': domain,
            'recursive': 'true',
            'filter': f"name=='{name}'"
        }
        resp = self._request('GET', '/v1/clients', params=params)
        if resp.status_code == 200:
            content = resp.json().get('content', [])
            if content:
                return content[0]
        return None

    def get_domains(self, path='/'):
        # Get immediate sub-domains of a path
        params = {
            'domain': path,
            'recursive': 'false'
        }
        resp = self._request('GET', '/v1/domains', params=params)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                return data
            return data.get('content', [])
        return []


    def get_client_groups(self, cid):
        """Get backup groups this client belongs to"""
        resp = self._request('GET', f"/v1/clients/{cid}/groups")
        if resp.status_code == 200:
            return resp.json().get('content', [])
        return []

    def get_client_backups(self, cid):
        resp = self._request('GET', f"/v1/clients/{cid}/backups")
        if resp.status_code == 200:
            return resp.json().get('content', [])
        return []


    def get_replication_destinations(self):
        resp = self._request('GET', '/v1/replication/destinations')
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                return data
            return data.get('content', [])
        return []

    def get_replication_groups(self):
        resp = self._request('GET', '/v1/replication/groups')
        if resp.status_code == 200:
             data = resp.json()
             if isinstance(data, list): return data
             return data.get('content', [])
        return []

    def delete_replication_group(self, group_id_or_name):
        resp = self._request('DELETE', f'/v1/replication/groups/{group_id_or_name}')
        return resp
        
    def delete_client(self, client_cid, domain):
        resp = self._request('DELETE', f'/v1/clients/{client_cid}', params={'domain': domain})
        return resp

    def get_client_by_id(self, cid):
        # Try direct access
        resp = self._request('GET', f'/v1/clients/{cid}')
        if resp.status_code == 200:
            return resp.json()
        return None

    def create_replication_destination(self, name, address, user, password, ddr_index=None):
        # We need to register the destination on the source system so it knows where to send data.
        # This typically involves:
        # 1. Defining the system name/IP
        # 2. Providing replication credentials (user/pass of the DESTINATION system)
        
        # Note: The endpoint is typically /v1/replication/destinations
        
        payload = {
            "name": name,
            "description": f"Target: {address}",
            "host": address,
            "username": user,
            "password": password
        }
        
        resp = self._request('POST', '/v1/replication/destinations', json_data=payload)
        return resp

    def get_schedules(self):
        clients = []
        page = 0
        all_sch = []
        while True:
            params = {'page': page, 'size': 100}
            resp = self._request('GET', '/v1/schedules', params=params)
            if resp.status_code != 200:
                print(f"Error fetching schedules: {resp.text}")
                break
                
            data = resp.json()
            curr = data.get('content', [])
            if not curr:
                break
            all_sch.extend(curr)
            if data.get('last', True):
                break
            page += 1
        return all_sch

    def create_replication_group(self, name, client_cids, dest_id):
        # 1. Use Default Schedule
        # User specified hardcoded ID for stability
        schedule_id = "Default:REPL_SCHEDULEID"
        print(f"Using Hardcoded Schedule ID: {schedule_id}")

        # Construct Payload matching user's Chrome DevTools observation
        payload = {
            "allBackups": True,
            "allClients": False,
            "backupFilter": {
                "dailyTag": True,
                "weeklyTag": True,
                "monthlyTag": True,
                "yearlyTag": True,
                "noTag": True,
                "maxBackupsPerClient": 0,
                "dateRestriction": "NONE",
                "within": 7,
                "durationUnit": "DAYS",
                "after": None,
                "before": None
            },
            "members": client_cids,
            "enabled": True,
            "encryption": "HIGH",
            "freeFlags": [],
            "name": name,
            "optimizeVsr": False,
            "orderingCriterion": "OLDEST_TO_NEWEST",
            "destinationServerId": dest_id,
            "replFlags": [
                {"pluginNumber": 1008, "key": "[avtar]pluginid-list", "value": "", "command": "BACKUP"},
                {"pluginNumber": 1008, "key": "[avtar]exclude-pluginid-list", "value": "", "command": "BACKUP"},
                {"pluginNumber": 1008, "key": "exclude", "value": "", "command": "BACKUP"},
                {"pluginNumber": 1008, "key": "[avtar]labelnumber", "value": "", "command": "BACKUP"},
                {"pluginNumber": 1008, "key": "[avtar]label", "value": "", "command": "BACKUP"},
                {"pluginNumber": 1008, "key": "[avtar]label-pattern", "value": "", "command": "BACKUP"},
                {"pluginNumber": 1008, "key": "[avtar]informationals", "value": "2", "command": "BACKUP"},
                {"pluginNumber": 1008, "key": "[avtar]statistics", "value": False, "command": "BACKUP"},
                {"pluginNumber": 1008, "key": "[avtar]verbose", "value": "0", "command": "BACKUP"},
                {"pluginNumber": 1008, "key": "debug", "value": False, "command": "BACKUP"},
                {"pluginNumber": 1008, "key": "max-streams", "value": "1", "command": "BACKUP"},
                {"pluginNumber": 1008, "key": "[avtar]throttle", "value": "0.0", "command": "BACKUP"},
                {"pluginNumber": 1008, "key": "targets-ordering", "value": "start", "command": "BACKUP"},
                {"pluginNumber": 1008, "key": "max-ddr-streams", "value": "8", "command": "BACKUP"}
            ],
            "retention": {
                "dailyTag": 60,
                "dailyTagUnit": "DAYS",
                "monthlyTag": 60,
                "monthlyTagUnit": "DAYS",
                "noTag": 60,
                "noTagUnit": "DAYS",
                "override": False,
                "weeklyTag": 60,
                "weeklyTagUnit": "DAYS",
                "yearlyTag": 60,
                "yearlyTagUnit": "DAYS"
            },
            "scheduleId": schedule_id, 
            "usePoolBased": False,
            "domainFqdn": "/"
        }
        
        print(f"Creating Replication Group [{name}] with embedded retention and Default Schedule...")
        resp = self._request('POST', '/v1/replication/groups', json_data=payload)
        return resp

    def create_retention_policy(self, name):
        """Creates a dedicated Replication Retention Policy based on user example"""
        # User provided example uses 'expireDate' even for DURATION type.
        # We will generate a future date just in case it's required by validation
        import datetime
        future_date = (datetime.datetime.now() + datetime.timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        payload = {
            "basicRetentionType": "DURATION",
            "dailyTag": 60,
            "dailyTagUnit": "DAYS",
            "domainFqdn": "/", 
            "duration": 60,
            "durationUnit": "DAYS",
            "expireDate": future_date, 
            "monthlyTag": 0,
            "monthlyTagUnit": "MONTHS",
            "name": name,
            "override": True,
            "weeklyTag": 0,
            "weeklyTagUnit": "WEEKS",
            "yearlyTag": 0,
            "yearlyTagUnit": "YEARS",
            "policyType" : "REPLICATION"
        }
        print(f"Creating new Retention Policy: {name} in domain /")
        resp = self._request('POST', '/v1/retentions', json_data=payload)
        if resp.status_code == 201:
            return resp.json() # Should return the created policy object
        elif resp.status_code == 200:
             return resp.json()
        print(f"Failed to create retention policy: {resp.status_code} {resp.text}")
        return None
        
    def get_retention_policies(self):
        all_ret = []
        page = 0
        while True:
            params = {'page': page, 'size': 100}
            resp = self._request('GET', '/v1/retentions', params=params)
             # If 404 or error, break
            if resp.status_code != 200: break
            
            data = resp.json()
            curr = data.get('content', [])
            if not curr: break
            
            all_ret.extend(curr)
            if data.get('last', True): break
            page += 1
        return all_ret

    def run_replication_group(self, group_id):
         resp = self._request('POST', f"/v1/replication/groups/{group_id}/run")
         return resp

    def get_replication_groups(self):
        groups = []
        page = 0
        while True:
            params = {'page': page, 'size': 100}
            resp = self._request('GET', '/v1/replication/groups', params=params)
            if resp.status_code != 200: break
            
            data = resp.json()
            curr = data.get('content', [])
            if not curr: break
            
            groups.extend(curr)
            if data.get('last', True): break
            page += 1
        return groups

    def get_replication_group_details_full(self, group_name):
        """Returns complex object with status, start/end times"""
        # 1. Find the group first to confirm existence
        groups = self.get_replication_groups()
        target_group = next((g for g in groups if g.get('name') == group_name), None)
        
        info = {
            "status": "Unknown",
            "ui_status": "Never Run",
            "startTime": None,
            "endTime": None,
            "bytes_scanned": 0,
            "bytes_sent": 0
        }

        if not target_group:
            info['status'] = "Group Not Found"
            return info
            
        # 2. Check Activity for this group
        # Use targeted filtering as per user requirement
        fqdn = f"/{group_name}" if not group_name.startswith('/') else group_name
        
        params = {
            'domain': '/', 
            'duration': 0,
            'recursive': 'true', 
            'filter': [
                "pluginName=='Replicate'",
                f"groupFqdn=='{fqdn}'"
            ]
        }
        
        resp = self._request('GET', '/v1/activities', params=params)
        matches = []
        
        if resp.status_code == 200:
            matches = resp.json().get('content', [])
            print(f"DEBUG: Found {len(matches)} activities for group {group_name}")

        if matches:
            # Sort manually by activatedDate or queuedDate (ISO strings)
            # Latest date first
            def get_sort_key(a):
                return a.get('activatedDate') or a.get('queuedDate') or a.get('scheduledDate') or a.get('startedTime') or ""
                
            matches.sort(key=get_sort_key, reverse=True)
            found_activity = matches[0]
            
            # Debug
            print(f"DEBUG: Found Activity keys: {list(found_activity.keys())}")
            print(f"DEBUG: Selected Activity Status: {found_activity.get('status')} / {found_activity.get('state')}")

            # Avamar API 7.x+ uses 'state' for activity status, older or different endpoints use 'status'
            st = found_activity.get('state') or found_activity.get('status')
            
            info['status'] = st
            info['startTime'] = get_sort_key(found_activity)
            info['endTime'] = found_activity.get('completedDate') or found_activity.get('completedTime')
            
            # Calculate Duration
            # Prefer elapsed time from API if available
            elapsed_ms = found_activity.get('elapsedTime')
            if elapsed_ms:
                 # It says int64, usually ms in Java world, but "elapsed time since queued" might be seconds? 
                 # Avamar rest api docs usually use ms for durations? or seconds?
                 # Let's assume ms if huge, seconds if small.
                 # Actually, usually 'elapsedTime' in these DTOs is milliseconds.
                 seconds = int(elapsed_ms) / 1000
                 m, s = divmod(seconds, 60)
                 h, m = divmod(m, 60)
                 info['duration'] = f"{int(h)}h {int(m)}m {int(s)}s"
            
            elif info['startTime'] and info['endTime']:
                try:
                    # Simple parser for ISO 8601
                    def parse_iso(ps):
                        # Handle fractional seconds if needed or 'Z'
                        return datetime.fromisoformat(ps.replace('Z', '+00:00'))
                        
                    start_dt = parse_iso(info['startTime'])
                    end_dt = parse_iso(info['endTime'])
                    diff = end_dt - start_dt
                    
                    # Format as HH:MM:SS
                    total_seconds = int(diff.total_seconds())
                    hours, remainder = divmod(total_seconds, 3600)
                    minutes, seconds = divmod(remainder, 60)
                    info['duration'] = f"{hours}h {minutes}m {seconds}s"
                except Exception as e:
                    info['duration'] = None
            else:
                info['duration'] = None

            # Extract stats
            stats = found_activity.get('stats', {})
            info['bytes_scanned'] = stats.get('bytesProcessed', 0)
            info['bytes_sent'] = stats.get('bytesSent', 0)
            
            # Try to map status to simpler UI terms
            if st in ['RUNNING', 'QUEUED']:
                info['ui_status'] = "Active"
            elif st in ['FAILED', 'COMPLETED_WITH_ERRORS']:
                info['ui_status'] = "Failed"
            elif st in ['COMPLETED', 'SUCCESS']:
                info['ui_status'] = "Completed"
            else:
                info['ui_status'] = st
        else:
            info['status'] = "NEVER_RUN"
            info['ui_status'] = "Never Run"

        return info

    def get_replication_group_status(self, group_name):
        # Wrapper for backward compatibility or simple lists
        details = self.get_replication_group_details_full(group_name)
        return details.get('ui_status', 'Unknown')

    def get_system_status(self):
        resp = self._request('GET', '/v1/system/status')
        if resp.status_code == 200:
            return resp.json()
        return None

    def stop_replication_activity(self, group_name):
        """Finds and cancels running activity for group"""
        # 1. Find the running activity
        fqdn = f"/{group_name}" if not group_name.startswith('/') else group_name
        
        # We need to find valid running/queued activities
        params = {
            'domain': '/', 
            'duration': 0,
            'recursive': 'true', 
            'filter': [
                "pluginName=='Replicate'",
                f"groupFqdn=='{fqdn}'"
            ]
        }
        
        resp = self._request('GET', '/v1/activities', params=params)
        
        if resp.status_code != 200:
            return {"error": f"Failed to search activities: {resp.text}"}
            
        activities = resp.json().get('content', [])
        
        # Active states: RUNNING, QUEUED, WAITING
        active_states = ['RUNNING', 'QUEUED', 'WAITING']
        
        target_activity = None
        for act in activities:
            state = act.get('state') or act.get('status')
            if state in active_states:
                target_activity = act
                break
        
        if not target_activity:
            return {"error": "No running activity found for this group."}
            
        act_id = target_activity.get('id')
        if not act_id:
             return {"error": "Activity found but has no ID."}
             
        # 2. Cancel it
        # Try /v1/activities/{id}/cancel
        resp_cancel = self._request('POST', f'/v1/activities/{act_id}/cancel')
        
        if resp_cancel.status_code in [200, 202, 204]:
             return {"status": "success", "message": "Stop command sent."}
        else:
             return {"error": f"Failed to stop activity: {resp_cancel.status_code} {resp_cancel.text}"}

