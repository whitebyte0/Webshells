# Plan: Database Client Tab

## Context
After implementing framework detection (which extracts DB credentials from config files), the natural next step is a Database Client tab that lets operators query databases directly from the shell. The framework detection already provides host, name, user, and password — the DB client consumes these.

## Concept
A new **Database** tab in the shell UI that supports MySQL, PostgreSQL, and SQLite via PHP's PDO extension. Features:
- Connect form with driver selector, host, port, database, user, password fields
- "Auto-fill from detected framework" button (uses data from diagnostics)
- SQL query textarea with Execute button
- Results rendered as a table
- Query history (stored in IndexedDB)
- Common quick queries (SHOW TABLES, SHOW DATABASES, SELECT version(), etc.)

## Architecture

### New module: `database`
This is an **optional module** (like tunnel, diagnostics, history) that can be excluded via `--exclude database`.

### New files
- **`src/backend/php/database.php`** — handles `action=dbconnect` (test connection, list tables), `action=dbquery` (execute SQL)
- **`src/frontend/js/database.js`** — DB tab UI logic, auto-fill from diagnostics, query execution, result rendering
- **`src/frontend/html/layout.html`** — add `<!-- MODULE:database -->` tab in sidebar + tab content

### Modified files
- **`src/config/defaults.json`** — add `"database": { "required": false, "description": "Database client (MySQL/PostgreSQL/SQLite via PDO)" }`
- **`src/backend/php/_order.json`** — add `"database"`
- **`src/frontend/js/_order.json`** — add `"database"`
- **`generate.py`** — add `'database': ['database.php']` to `MODULE_BACKEND` and `'database': ['database.js']` to `MODULE_JS`

### Backend design: `database.php`

#### `action=dbconnect`
```
POST: action=dbconnect, driver=(mysql|pgsql|sqlite), host, port, dbname, user, pass
Response: { ok: true, tables: [...], server_version: "..." }
```
- Builds PDO DSN from params
- Tests connection with `new PDO($dsn, $user, $pass)`
- Lists tables via driver-specific query:
  - MySQL: `SHOW TABLES`
  - PostgreSQL: `SELECT tablename FROM pg_tables WHERE schemaname='public'`
  - SQLite: `SELECT name FROM sqlite_master WHERE type='table'`
- Returns table list + server version (`$pdo->getAttribute(PDO::ATTR_SERVER_VERSION)`)

#### `action=dbquery`
```
POST: action=dbquery, driver, host, port, dbname, user, pass, sql, limit(default 100)
Response: { columns: [...], rows: [[...], ...], affected: N, time_ms: N }
```
- Creates fresh PDO connection (no persistent state)
- For SELECT/SHOW: returns columns + rows (capped at limit)
- For INSERT/UPDATE/DELETE: returns affected row count
- Timeout: `set_time_limit(30)`
- Error handling: catches `PDOException`, returns `{ error: "..." }`

### Frontend design: `database.js`

#### Connection form
- Driver dropdown: MySQL, PostgreSQL, SQLite
- Host, Port, Database, User, Password fields
- SQLite: host/port/user/pass hidden, shows file path input instead
- "Auto-fill" button: calls diagnostics data, populates fields from detected framework DB creds
- "Connect" button: sends `dbconnect`, shows table list on success

#### Query interface (shown after connection)
- SQL textarea with Ctrl+Enter shortcut
- Quick query buttons: `SHOW TABLES`, `SHOW DATABASES`, `SELECT version()`, `DESCRIBE tablename`
- Execute button
- Results table with sortable columns
- Row count + execution time display
- Query history in the tab

#### State management
- Connection params stored in JS variables (not persisted — reconnects each query)
- Each query sends full connection params (stateless backend)
- Table list cached until reconnect

### HTML layout additions

Sidebar nav entry (inside MODULE:database markers):
```html
<!-- MODULE:database -->
      <li><a href="#" data-tab="database"><span class="icon">&#x1F5C4;</span>Database</a></li>
<!-- /MODULE:database -->
```

Tab content:
```html
<!-- MODULE:database -->
      <div class="tab-content" id="tab-database">
        <!-- Connection form card -->
        <!-- Query card (hidden until connected) -->
        <!-- Results card -->
      </div>
<!-- /MODULE:database -->
```

### Edge cases
- **PDO not available**: Check `extension_loaded('pdo')` + driver-specific extensions (`pdo_mysql`, `pdo_pgsql`, `pdo_sqlite`). Show clear message if missing.
- **Large result sets**: Default limit of 100 rows, configurable. Prevents memory exhaustion.
- **SQL injection in the client itself**: Not a concern — this IS a shell. The operator is intentionally running arbitrary SQL.
- **Binary data in results**: Base64-encode binary columns or show `[BLOB N bytes]` placeholder.
- **Multi-statement queries**: PDO allows them with `PDO::ATTR_EMULATE_PREPARES`. Support `INSERT ... SELECT`, `CREATE TABLE`, etc.
- **Connection timeout**: Set `PDO::ATTR_TIMEOUT => 5` to avoid hanging on unreachable hosts.

### Auto-fill integration with Framework Detection
The diagnostics `action=diag` response already includes `frameworks[].details.db_host`, `db_name`, `db_user`, `db_pass`. The JS auto-fill button:
1. Fetches diagnostics (or uses cached result if already loaded)
2. Finds first framework with DB credentials
3. Populates the connection form
4. Infers driver from framework type (WordPress/Joomla/Drupal → MySQL, Laravel → from `db_driver` field)

### Verification
```bash
# Build with database module
python generate.py --output test_db.php

# Build without database module
python generate.py --exclude database --output test_nodb.php
# Verify no database tab or backend code

# Deploy test_db.php to a server with MySQL access
# Test: connect with credentials, run SHOW TABLES, run SELECT query
# Test: auto-fill from detected WordPress config
# Test: SQLite mode with a .sqlite file path
```
