import json
import os
import uuid
from cryptography.fernet import Fernet

CONFIG_FILE = 'config.json'
KEY_FILE = 'secret.key'


class SettingsManager:
    def __init__(self):
        self._load_key()
        self.cipher_suite = Fernet(self.key)
        self.config = self._load_config()

    def _load_key(self):
        if os.path.exists(KEY_FILE):
            with open(KEY_FILE, 'rb') as key_file:
                self.key = key_file.read()
        else:
            self.key = Fernet.generate_key()
            with open(KEY_FILE, 'wb') as key_file:
                key_file.write(self.key)

    def _load_config(self):
        if not os.path.exists(CONFIG_FILE):
            return {"sources": [], "destinations": []}
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {"sources": [], "destinations": []}

    def _save_config(self):
        with open(CONFIG_FILE, 'w') as f:
            json.dump(self.config, f, indent=4)

    def _encrypt(self, text):
        if not text:
            return ""
        return self.cipher_suite.encrypt(text.encode()).decode()

    def _decrypt(self, text):
        if not text:
            return ""
        try:
            return self.cipher_suite.decrypt(text.encode()).decode()
        except Exception:
            return text

    def _generate_id(self, items):
        """Generate a unique ID that won't collide after deletions."""
        existing_ids = {item.get('id') for item in items if item.get('id')}
        new_id = str(uuid.uuid4())[:8]  # Use first 8 chars of UUID
        # Ensure uniqueness in unlikely case of collision
        while new_id in existing_ids:
            new_id = str(uuid.uuid4())[:8]
        return new_id

    def get_sources(self):
        return self.config.get('sources', [])

    def get_destinations(self):
        return self.config.get('destinations', [])

    def get_source_by_id(self, id):
        for s in self.config.get('sources', []):
            if s['id'] == id:
                s_copy = s.copy()
                s_copy['password'] = self._decrypt(s['password'])
                return s_copy
        return None
    
    def get_destination_by_id(self, id):
        for d in self.config.get('destinations', []):
            if d['id'] == id:
                d_copy = d.copy()
                d_copy['password'] = self._decrypt(d['password'])
                return d_copy
        return None

    def add_source(self, data):
        if not isinstance(data, dict):
            raise ValueError("Data must be a dictionary")
        
        name = data.get('name')
        host = data.get('host')
        user = data.get('user')
        password = data.get('password')
        
        if not all([name, host, user, password]):
            raise ValueError("Missing required fields: name, host, user, password")

        entry = {
            "id": self._generate_id(self.config.get('sources', [])),
            "name": name,
            "host": host,
            "user": user,
            "password": self._encrypt(password)
        }
        self.config.setdefault('sources', []).append(entry)
        self._save_config()
        return entry

    def add_destination(self, data):
        if not isinstance(data, dict):
            raise ValueError("Data must be a dictionary")
        
        name = data.get('name')
        host = data.get('host')
        user = data.get('user')
        password = data.get('password')
        
        if not all([name, host, user, password]):
            raise ValueError("Missing required fields: name, host, user, password")

        entry = {
            "id": self._generate_id(self.config.get('destinations', [])),
            "name": name,
            "host": host,
            "user": user,
            "password": self._encrypt(password)
        }
        self.config.setdefault('destinations', []).append(entry)
        self._save_config()
        return entry

    def delete_setting(self, type, id):
        lst = self.config.get(type, [])
        self.config[type] = [x for x in lst if x['id'] != str(id)]
        self._save_config()

    def reset_defaults(self):
        self.config = {"sources": [], "destinations": []}
        self._save_config()

    def delete_source(self, id):
        self.config['sources'] = [s for s in self.config['sources'] if s['id'] != id]
        self._save_config()

    def delete_destination(self, id):
        self.config['destinations'] = [d for d in self.config['destinations'] if d['id'] != id]
        self._save_config()
