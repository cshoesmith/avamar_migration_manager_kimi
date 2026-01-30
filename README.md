# Avamar Migrator

This application helps identify inactive Avamar clients (retired) that still possess backups and replicates them to a destination Avamar server.

## Setup

1.  **Install Requests and Flask**:
    ```bash
    pip install flask requests urllib3
    ```

2.  **Configuration**:
    Open `app.py` and modify the following constants at the top of the file to match your environment:
    ```python
    SOURCE_AVAMAR_HOST = "192.168.0.200"
    SOURCE_AVAMAR_USER = "admin"
    SOURCE_AVAMAR_PASS = "admin"
    
    DEST_AVAMAR_HOST = "192.168.0.205"
    DEST_AVAMAR_USER = "repl_user"
    DEST_AVAMAR_PASS = "repl_pass"
    ```

3.  **Run the Application**:
    ```bash
    python app.py
    ```
    The web interface will be available at `http://localhost:5000`.

## Features

*   **Discovery**: Scans for clients marked as `restoreOnly` (inactive) that have `totalBackups > 0`.
*   **Replication**: Allows selecting found clients and adding them to a new Replication Group targeted at a specific destination.
*   **Monitoring**: Basic dashboard framework to view created groups.

## Notes

*   **Authentication**: The current implementation uses a placeholder Basic Auth / Token stub. You may need to adjust `_get_token` in `avamar_client.py` depending on your specific Avamar version's authentication flow (OAuth2 vs Basic).
*   **Destinations**: The app expects replication destinations to be pre-configured on the source Avamar or retrievable via valid GET endpoints.
*   **Scheduling**: Replication groups are created with a placeholder schedule ID. You will need to provide a valid Schedule ID from your Avamar system in `avamar_client.py` or extend the UI to select one.
