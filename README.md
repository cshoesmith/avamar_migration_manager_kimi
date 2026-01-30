# Avamar Migrator

This application helps identify inactive Avamar clients (retired) that still possess backups and replicates them to a destination Avamar server.

## Setup

1.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

2.  **Configuration**:
    Copy `.env.example` to `.env` and configure your environment:
    ```bash
    cp .env.example .env
    ```
    
    Edit `.env` with your values:
    ```env
    # Generate a strong secret key
    SECRET_KEY=your-generated-secret-key
    
    # Avamar OAuth credentials (change defaults for production)
    AVAMAR_CLIENT_ID=AvamarMigrator
    AVAMAR_CLIENT_SECRET=your-secure-secret
    
    # SSL Verification (keep True for production)
    VERIFY_SSL=True
    ```

3.  **Initialize Database**:
    The database will be automatically initialized on first run. A random admin password will be generated and displayed in the console if `DEFAULT_ADMIN_PASSWORD` is not set.

4.  **Run the Application**:
    ```bash
    python app.py
    ```
    The web interface will be available at `http://localhost:5000`.

## Features

*   **Discovery**: Scans for clients marked as `restoreOnly` (inactive) that have `totalBackups > 0`.
*   **Replication**: Allows selecting found clients and adding them to a new Replication Group targeted at a specific destination.
*   **Monitoring**: Dashboard to view created groups and track replication progress.
*   **Audit Logging**: All administrative actions are logged for compliance.

## Security Notes

*   **Passwords**: All passwords are encrypted at rest using Fernet encryption.
*   **SSL**: SSL certificate verification is enabled by default. Only disable (`VERIFY_SSL=False`) for testing with self-signed certificates.
*   **Secrets**: Never commit `.env` or `secret.key` files to version control.
*   **Default Passwords**: The application no longer uses hardcoded default passwords. Set `DEFAULT_ADMIN_PASSWORD` or a random password will be generated on first run.

## Configuration Files

*   `config.json` - Stores source and destination Avamar server configurations (passwords encrypted).
*   `secret.key` - Encryption key for passwords (auto-generated).
*   `migration_status.db` - SQLite database for job tracking.

## API Endpoints

*   `GET/POST /api/settings/sources` - Manage source Avamar servers
*   `GET/POST /api/settings/destinations` - Manage destination Avamar servers
*   `POST /api/scan` - Scan for migration candidates
*   `POST /api/replicate` - Create replication group
*   `GET /api/replication/status` - Get replication status
*   `GET /api/jobs/<group_name>` - Get job details
*   `POST /api/jobs/<group_name>/run` - Run replication job
*   `POST /api/jobs/<group_name>/cancel` - Cancel replication job
