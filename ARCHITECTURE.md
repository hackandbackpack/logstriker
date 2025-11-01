# LogStriker Architecture

## Purpose
Parse Cobalt Strike Beacon logs from multiple files and organize them chronologically for penetration testing analysis.

## Critical Requirements

### 1. Multi-line Entry Preservation
- Lines with timestamps (`MM/DD HH:MM:SS UTC [type]`) start new entries
- Lines without timestamps are continuations of previous entry
- ALL content must be preserved exactly (whitespace, blank lines, formatting)

### 2. Chronological Ordering
- Combine all beacon logs per IP address in chronological order
- Must handle entries spanning multiple beacon sessions
- Final output shows complete chain of events per host

### 3. Directory Structure
```
/opt/tools/cobaltstrike/server/logs/
├── YYMMDD/                    (e.g., 251028 = Oct 28, 2025)
│   ├── IP_ADDRESS/            (e.g., 192.168.1.100)
│   │   ├── beacon_1234.log
│   │   ├── beacon_5678.log
│   │   └── ...
│   ├── download.log
│   ├── weblog_80.log
│   ├── weblog_443.log
│   └── events.log
└── ...
```

### 4. Output Files
- `{IP}_combined.log` - All beacon activity for each IP
- `download_combined.log` - All download logs
- `weblog_80_combined.log` - All HTTP logs
- `weblog_443_combined.log` - All HTTPS logs
- `events_combined.log` - All event logs

## Components

### 1. SSHManager
**Purpose**: Handle SSH connections to Cobalt Strike teamserver

**Key Methods**:
- `connect(ssh_config_host)` - Connect using SSH config entry
- `execute_command(cmd)` - Execute remote command, return output
- `find_file(pattern)` - Search for files matching pattern
- `download_file(remote_path, local_path)` - Download file
- `close()` - Close connection

**Error Handling**:
- Connection failures
- Authentication issues
- Network timeouts

### 2. LogDiscovery
**Purpose**: Find and inventory all Cobalt Strike logs

**Key Methods**:
- `find_logs_directory(ssh_manager)` - Locate logs dir (default: /opt/tools/cobaltstrike/server/logs)
- `scan_structure(logs_path)` - Build inventory of all logs
- `get_date_folders()` - Return list of YYMMDD folders
- `get_ip_folders(date_folder)` - Return list of IP addresses
- `get_beacon_logs(ip_folder)` - Return beacon_*.log files for IP

**Returns**: Dictionary structure:
```python
{
    'beacon_logs': {
        '192.168.1.100': [
            {'path': '/path/to/beacon_1.log', 'date_folder': '251028'},
            {'path': '/path/to/beacon_2.log', 'date_folder': '251028'}
        ]
    },
    'system_logs': {
        'download': ['/path/251028/download.log', '/path/251029/download.log'],
        'weblog_80': [...],
        'weblog_443': [...],
        'events': [...]
    }
}
```

### 3. LogEntry (Data Model)
```python
@dataclass
class LogEntry:
    timestamp: datetime           # Full UTC timestamp
    entry_type: str              # input, task, checkin, output, etc.
    content: List[str]           # All lines (first line + continuations)
    source_file: str             # Original file path for debugging
    ip_address: Optional[str]    # Associated IP (for beacon logs)

    def format(self) -> str:
        """Reconstruct entry in original format"""
        # First line with timestamp
        first = f"{self.timestamp.strftime('%m/%d %H:%M:%S')} UTC [{self.entry_type}] {self.content[0]}"
        # Continuation lines
        rest = '\n'.join(self.content[1:]) if len(self.content) > 1 else ''
        return first + ('\n' + rest if rest else '')
```

### 4. LogParser
**Purpose**: Parse individual log files into LogEntry objects

**Key Methods**:
- `parse_beacon_log(file_content, base_date, source_file, ip)` - Parse beacon log
- `parse_system_log(file_content, base_date, source_file)` - Parse system log
- `_parse_timestamp(mm_dd, time_str, base_year)` - Construct full datetime
- `_is_timestamp_line(line)` - Check if line starts new entry

**Algorithm**:
1. Regex pattern: `^(\d{2}/\d{2})\s+(\d{2}:\d{2}:\d{2})\s+UTC\s+\[([^\]]+)\]\s+(.*)$`
2. For each line:
   - If matches pattern: save previous entry, start new entry
   - If doesn't match: append to current entry's content
3. Don't forget last entry!

**Edge Cases**:
- Empty files
- Malformed timestamps
- Missing brackets
- Logs spanning midnight

### 5. LogAggregator
**Purpose**: Combine and sort log entries

**Key Methods**:
- `aggregate_by_ip(entries_by_ip)` - Combine all entries per IP, sort chronologically
- `aggregate_system_logs(entries_by_type)` - Combine system logs by type
- `_sort_entries(entries)` - Sort by timestamp

**Process**:
1. Group all LogEntry objects by IP address
2. Sort each group by timestamp
3. Verify chronological order
4. Return sorted collections

### 6. LogWriter
**Purpose**: Write combined logs to local files

**Key Methods**:
- `write_ip_logs(aggregated_entries, output_dir)` - Write per-IP logs
- `write_system_logs(aggregated_entries, output_dir)` - Write system logs
- `_write_entries(entries, file_path)` - Write entries to file

**Format**:
- Use LogEntry.format() to reconstruct original appearance
- Preserve blank lines between entries
- Add header with metadata (optional)

### 7. CLI Interface
**Purpose**: User interaction and orchestration

**Flow**:
1. Prompt for SSH config entry name
2. Connect to teamserver
3. Find logs directory (or search)
4. Scan and inventory logs
5. Download logs
6. Parse logs
7. Aggregate by IP/type
8. Write output files
9. Display summary

**Progress Messages**:
```
[*] Connecting to teamserver via SSH config: prod-ts
[+] Connected successfully to 10.0.0.100
[*] Locating Cobalt Strike logs directory...
[+] Found logs at: /opt/tools/cobaltstrike/server/logs
[*] Scanning log structure...
[+] Found 3 date folders: 251026, 251027, 251028
[+] Found 5 unique IP addresses
[+] Found 47 beacon logs, 12 system logs
[*] Downloading logs (this may take a moment)...
[+] Downloaded 47 beacon logs (12.3 MB)
[+] Downloaded 12 system logs (2.1 MB)
[*] Parsing beacon logs...
[+] Parsed 2,341 log entries from 47 files
[*] Parsing system logs...
[+] Parsed 892 log entries from 12 files
[*] Aggregating logs by IP address...
[+] Created 5 combined IP logs:
    - 192.168.1.100 (453 entries)
    - 192.168.1.101 (234 entries)
    - ...
[*] Aggregating system logs...
[+] Created 4 combined system logs
[*] Writing output to: /c/Users/Pentester/Code/logstriker
[+] Wrote 9 files successfully
[+] Complete! Total entries: 3,233
```

## Error Handling

### SSH Errors
```
[!] Failed to connect to teamserver 'prod-ts'
    Error: Host not found in SSH config

    Troubleshooting:
    1. Check SSH config file (~/.ssh/config)
    2. Verify host entry exists
    3. Test connection: ssh prod-ts
```

### Missing Logs Directory
```
[-] Default logs path not found: /opt/tools/cobaltstrike/server/logs
[*] Searching for Cobalt Strike logs...
[-] Could not locate logs directory automatically

    Please enter the full path to the logs directory:
```

### Parsing Errors
```
[-] Warning: Malformed entry in beacon_1234.log line 342
    Skipping entry and continuing...
```

## Dependencies
- `paramiko` - SSH connectivity
- `python-dateutil` - Date parsing utilities
- Standard library: `os`, `sys`, `pathlib`, `re`, `datetime`, `argparse`, `dataclasses`

## Implementation Notes

### Timestamp Handling
- Base year from YYMMDD folder name (e.g., 251028 → 2025)
- Parse MM/DD from log entries
- Handle logs spanning midnight (allow ±1 day from folder date)
- Always use UTC timezone

### Memory Efficiency
- Process files one at a time
- Stream large files if needed
- Use generators where possible
- Clear buffers after processing

### Testing Strategy
1. Unit tests for LogParser with various log formats
2. Test multi-line entry parsing
3. Test timestamp edge cases (midnight rollover)
4. Integration test with sample log structure
5. Error handling tests

## Security Considerations
- No credentials stored in code
- Use SSH keys from user's config
- Sanitize file paths to prevent directory traversal
- Validate remote file sizes before download
- Handle sensitive data appropriately (this is pentest data)
