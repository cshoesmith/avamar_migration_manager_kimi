import requests
import urllib3
import base64
import os
from datetime import datetime

# SSL verification - configurable via environment variable
VERIFY_SSL = os.environ.get('VERIFY_SSL', 'True').lower() in ('true', '1', 'yes')
if not VERIFY_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class AvamarClient:
    def __init__(self, host, username, password, role='source'):
        self.host = host
        self.base_url = f"https://{host}"
        self.username = username
        self.password = password
        self.token = None
        self.session = requests.Session()
        self.session.verify = VERIFY_SSL
        self.role = role  # 'source' or 'destination'
        
        # OAuth Client Credentials - distinct for source vs destination
        base_client_id = os.environ.get('AVAMAR_CLIENT_ID', 'AvamarMigrator')
        self.client_id = f"{base_client_id}_{role}"
        self.client_secret = os.environ.get('AVAMAR_CLIENT_SECRET', 'AvamarMigratorSecret123!')

    def get_system_status(self):
        """Checks if the system is reachable and authenticated."""
        try:
            if not self.token:
                self._authenticate()
            
            # Make a cheap call to verify API responsiveness
            resp = self._request('GET', '/v1/domains', params={'domain': '/', 'recursive': 'false'})
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception as e:
            print(f"System status check failed: {e}")
            raise

    def _authenticate(self):
        print(f"Starting Authentication logic for {self.host} (role: {self.role}, client_id: {self.client_id})...")
        
        # Try to get token first
        print("Step 1: Attempting to get access token...")
        token = self._get_access_token()
        if token:
            self.token = token
            print("Token retrieved successfully.")
            return True

        # If failed, try to register the client
        print("Step 2: Token retrieval failed. Attempting to register OAuth client...")
        if self._create_oauth_client():
            print("Step 3: Client registration succeeded. Retrying token retrieval...")
            token = self._get_access_token()
            if token:
                self.token = token
                print("Token retrieved successfully after registration.")
                return True
            else:
                print("Step 3: Token retrieval still failed after client registration.")
        else:
            print("Step 2: Client registration failed.")
        
        raise Exception(f"Authentication Failed: Could not get token or register client (client_id: {self.client_id}). Check Avamar credentials and ensure user has OAuth client management permissions.")

    def _create_oauth_client(self):
        url = f"{self.base_url}/api/v1/oauth2/clients"
        
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
            print(f"  Creating OAuth client: {self.client_id}")
            print(f"  Auth user: {self.username}")
            resp = self.session.post(url, json=payload, headers=headers)
            print(f"  Client registration response: {resp.status_code}")
            if resp.status_code in [200, 201]:
                print(f"  Client created successfully")
                return True
            if resp.status_code == 400:
                print(f"  Client likely already exists (400)")
                return True
            
            if resp.status_code == 401:
                print(f"  Client registration returned 401 (unauthorized) - user may lack permissions")
                print(f"  Response: {resp.text[:200]}")
                return True
            
            print(f"  Failed to create client: {resp.status_code} {resp.text[:200]}")
            return False
        except Exception as e:
            print(f"  Exception creating client: {e}")
            return False

    def _get_access_token(self):
        url = f"{self.base_url}/api/oauth/token"
        
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
            print(f"  Token request: client_id={self.client_id}, user={self.username}")
            resp = self.session.post(url, data=data, headers=headers)
            print(f"  Token response: {resp.status_code}")
            if resp.status_code == 200:
                token = resp.json().get('access_token')
                print(f"  Token received: {token[:20]}..." if token else "  No token in response")
                return token
            print(f"  Failed to get token: {resp.status_code} - {resp.text[:200]}")
            return None
        except Exception as e:
            print(f"  Exception getting token: {e}")
            return None

    def _request(self, method, endpoint, params=None, json_data=None):
        if not self.token:
            self._authenticate()

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
            except Exception as e:
                print(f"Re-authentication failed: {e}")
                raise
                
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
            current_batch = data.get('content', [])
            if not current_batch:
                break
                
            clients.extend(current_batch)
            if data.get('last', True):
                break
            page += 1
            
        return clients

    def get_client_by_name(self, name, domain='/'):
        """Find client by name with proper escaping to prevent injection."""
        # Escape single quotes in name to prevent filter injection
        safe_name = name.replace("'", "''")
        params = {
            'domain': domain,
            'recursive': 'true',
            'filter': f"name=='{safe_name}'"
        }
        resp = self._request('GET', '/v1/clients', params=params)
        if resp.status_code == 200:
            content = resp.json().get('content', [])
            if content:
                return content[0]
        return None

    def get_domains(self, path='/'):
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
        """Get all replication groups with pagination."""
        groups = []
        page = 0
        while True:
            params = {'page': page, 'size': 100}
            resp = self._request('GET', '/v1/replication/groups', params=params)
            if resp.status_code != 200:
                break
            
            data = resp.json()
            curr = data.get('content', [])
            if not curr:
                break
            
            groups.extend(curr)
            if data.get('last', True):
                break
            page += 1
        return groups

    def delete_replication_group(self, group_id_or_name):
        resp = self._request('DELETE', f'/v1/replication/groups/{group_id_or_name}')
        return resp
        
    def delete_client(self, client_cid, domain):
        resp = self._request('DELETE', f'/v1/clients/{client_cid}', params={'domain': domain})
        return resp

    def get_client_by_id(self, cid):
        resp = self._request('GET', f'/v1/clients/{cid}')
        if resp.status_code == 200:
            return resp.json()
        return None

    def create_replication_destination(self, name, address, user, password, ddr_index=None):
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
        schedule_id = "Default:REPL_SCHEDULEID"
        print(f"Using Hardcoded Schedule ID: {schedule_id}")

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
        """Creates a dedicated Replication Retention Policy."""
        future_date = (datetime.now() + __import__('datetime').timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

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
            "policyType": "REPLICATION"
        }
        print(f"Creating new Retention Policy: {name} in domain /")
        resp = self._request('POST', '/v1/retentions', json_data=payload)
        if resp.status_code == 201:
            return resp.json()
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
            if resp.status_code != 200:
                break
            
            data = resp.json()
            curr = data.get('content', [])
            if not curr:
                break
            
            all_ret.extend(curr)
            if data.get('last', True):
                break
            page += 1
        return all_ret

    def run_replication_group(self, group_id):
         resp = self._request('POST', f"/v1/replication/groups/{group_id}/run")
         return resp

    def get_replication_group_details_full(self, group_name):
        """Returns complex object with status, start/end times."""
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
            # Debug: Found activities for group

        if matches:
            def get_sort_key(a):
                return a.get('activatedDate') or a.get('queuedDate') or a.get('scheduledDate') or a.get('startedTime') or ""
                
            matches.sort(key=get_sort_key, reverse=True)
            found_activity = matches[0]
            
            # Activity found and parsed

            st = found_activity.get('state') or found_activity.get('status')
            
            info['status'] = st
            info['startTime'] = get_sort_key(found_activity)
            info['endTime'] = found_activity.get('completedDate') or found_activity.get('completedTime')
            
            elapsed_ms = found_activity.get('elapsedTime')
            if elapsed_ms:
                 seconds = int(elapsed_ms) / 1000
                 m, s = divmod(seconds, 60)
                 h, m = divmod(m, 60)
                 info['duration'] = f"{int(h)}h {int(m)}m {int(s)}s"
            
            elif info['startTime'] and info['endTime']:
                try:
                    def parse_iso(ps):
                        return datetime.fromisoformat(ps.replace('Z', '+00:00'))
                        
                    start_dt = parse_iso(info['startTime'])
                    end_dt = parse_iso(info['endTime'])
                    diff = end_dt - start_dt
                    
                    total_seconds = int(diff.total_seconds())
                    hours, remainder = divmod(total_seconds, 3600)
                    minutes, seconds = divmod(remainder, 60)
                    info['duration'] = f"{hours}h {minutes}m {seconds}s"
                except Exception:
                    info['duration'] = None
            else:
                info['duration'] = None

            stats = found_activity.get('stats', {})
            info['bytes_scanned'] = stats.get('bytesProcessed', 0)
            info['bytes_sent'] = stats.get('bytesSent', 0)
            
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
        details = self.get_replication_group_details_full(group_name)
        return details.get('ui_status', 'Unknown')

    def stop_replication_activity(self, group_name):
        """Finds and cancels running activity for group."""
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
        
        if resp.status_code != 200:
            return {"error": f"Failed to search activities: {resp.text}"}
            
        activities = resp.json().get('content', [])
        
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
             
        resp_cancel = self._request('POST', f'/v1/activities/{act_id}/cancel')
        
        if resp_cancel.status_code in [200, 202, 204]:
             return {"status": "success", "message": "Stop command sent."}
        else:
             return {"error": f"Failed to stop activity: {resp_cancel.status_code} {resp_cancel.text}"}

    def get_storage_info(self):
        """Get GSAN storage information including total and used capacity in bytes."""
        resp = self._request('GET', '/v1/system/gsan-storage-information')
        if resp.status_code == 200:
            return resp.json()
        return None
