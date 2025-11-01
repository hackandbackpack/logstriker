# LogStriker

A specialized tool for parsing and aggregating Cobalt Strike Beacon logs from multiple files into chronological order, designed for penetration testing post-engagement analysis.

## Overview

During penetration testing engagements, operators often perform actions across multiple beacons and sessions. LogStriker solves the challenge of reconstructing a complete timeline of events by:

- Combining all beacon logs per target host in chronological order
- Preserving multi-line command outputs exactly as they appeared
- Aggregating system logs (downloads, web requests, events) across all sessions
- Providing a clear chain of events for reporting and analysis

## Features

- **Chronological Aggregation**: Merges logs from multiple beacon sessions per IP address in timestamp order
- **Multi-line Preservation**: Correctly handles and preserves command outputs that span multiple lines
- **Remote Access**: Connects directly to Cobalt Strike teamserver via SSH
- **Automatic Discovery**: Finds and processes logs in standard Cobalt Strike directory structure
- **System Log Consolidation**: Combines download logs, weblog entries, and event logs across all dates
- **Error Resilience**: Handles malformed timestamps, empty files, and connection issues gracefully

## Requirements

- Python 3.7+ (uses only standard library)
- OpenSSH client (`ssh` and `scp` commands)
- SSH config entry for Cobalt Strike teamserver
- SSH key-based authentication configured

## Installation

```bash
# Clone the repository
git clone https://github.com/hackandbackpack/logstriker.git
cd logstriker

# Make executable (Linux/Mac)
chmod +x logstriker.py

# No additional Python packages required!
```

## Usage

### Basic Usage

```bash
python logstriker.py
```

You will be prompted to enter your SSH config host entry for the Cobalt Strike teamserver. The tool will then:

1. Connect to the teamserver
2. Locate the logs directory (default: `/opt/tools/cobaltstrike/server/logs`)
3. Scan for all beacon and system logs
4. Download and parse all logs
5. Aggregate by IP address and log type
6. Write combined logs to the current directory

### Example Session

```
============================================================
LogStriker - Cobalt Strike Log Aggregation Tool
============================================================

Enter SSH config host entry for teamserver: prod-teamserver

[*] Connecting to teamserver via SSH config: prod-teamserver
[+] Connected successfully

[*] Locating Cobalt Strike logs directory...
[+] Found logs at: /opt/tools/cobaltstrike/server/logs

[*] Scanning log structure...
[+] Found 3 date folders: 251026, 251027, 251028
[+] Found 5 unique IP addresses
[+] Found 47 beacon logs, 12 system logs

[*] Downloading and parsing beacon logs...
[+] Parsed 2341 entries from 5 IPs

[*] Downloading and parsing system logs...
[+] Parsed 892 entries from system logs

[*] Aggregating logs by IP address...
[+] Created 5 combined IP logs:
    - 192.168.1.100 (453 entries)
    - 192.168.1.101 (234 entries)
    - 192.168.1.102 (821 entries)
    - 192.168.1.103 (567 entries)
    - 192.168.1.104 (266 entries)

[*] Aggregating system logs...
[+] Created 4 combined system logs

[*] Writing output to: /home/operator/logstriker
    - 192.168.1.100 (453 entries) -> 192_168_1_100_combined.log
    - 192.168.1.101 (234 entries) -> 192_168_1_101_combined.log
    - 192.168.1.102 (821 entries) -> 192_168_1_102_combined.log
    - 192.168.1.103 (567 entries) -> 192_168_1_103_combined.log
    - 192.168.1.104 (266 entries) -> 192_168_1_104_combined.log
    - download (123 entries) -> download_combined.log
    - weblog_80 (245 entries) -> weblog_80_combined.log
    - weblog_443 (421 entries) -> weblog_443_combined.log
    - events (103 entries) -> events_combined.log

[+] Complete! Wrote 9 files
[+] Total entries processed: 3233
```

## Output Files

LogStriker generates the following output files in the current directory:

### Per-IP Beacon Logs
- `{IP_ADDRESS}_combined.log` - All beacon activity for each target host, chronologically ordered
- Example: `192_168_1_100_combined.log`

### System Logs
- `download_combined.log` - All file downloads across all sessions
- `weblog_80_combined.log` - All HTTP (port 80) web delivery logs
- `weblog_443_combined.log` - All HTTPS (port 443) web delivery logs
- `events_combined.log` - All Cobalt Strike event logs

## Cobalt Strike Log Structure

LogStriker expects logs in the standard Cobalt Strike directory structure:

```
/opt/tools/cobaltstrike/server/logs/
├── 251028/                    # YYMMDD format (Oct 28, 2025)
│   ├── 192.168.1.100/        # IP address of target host
│   │   ├── beacon_1234.log
│   │   ├── beacon_5678.log
│   │   └── ...
│   ├── 192.168.1.101/
│   │   └── beacon_9012.log
│   ├── download.log
│   ├── weblog_80.log
│   ├── weblog_443.log
│   └── events.log
├── 251029/
│   └── ...
└── ...
```

If your logs are in a different location, LogStriker will:
1. Search common alternative paths
2. Prompt you to manually enter the path

## SSH Configuration

LogStriker uses SSH config entries for authentication. Example `~/.ssh/config`:

```
Host prod-teamserver
    HostName 10.0.0.100
    User operator
    Port 22
    IdentityFile ~/.ssh/id_rsa_cs
```

Test your connection before running LogStriker:
```bash
ssh prod-teamserver
```

## Log Format

Beacon logs follow this format:
```
10/28 18:07:19 UTC [input] <j> sleep 0
10/28 18:07:19 UTC [task] <T1029> Tasked beacon to become interactive
10/28 18:08:11 UTC [checkin] host called home, sent: 16 bytes
10/28 18:08:45 UTC [output]
received output:
[+] Command completed successfully
Additional output line 1
Additional output line 2
```

LogStriker preserves:
- Timestamp and entry type (input/task/checkin/output)
- All content, including multi-line outputs
- Original formatting and whitespace

## Error Handling

LogStriker handles various error conditions gracefully:

- **Connection Failures**: Clear error messages with troubleshooting steps
- **Missing Logs Directory**: Automatic search and manual prompt
- **Malformed Timestamps**: Logs warning and continues processing
- **Empty Files**: Logs warning but continues
- **Download Failures**: Reports failed downloads but processes available logs
- **Partial Failures**: Continues processing remaining files after errors

## Performance

Typical performance for a moderate engagement:
- 100 beacon log files (~10MB total)
- Processing time: 10-20 seconds
- Output: 5-10 combined log files

Performance optimizations:
- Compiled regex patterns for fast parsing
- Buffered file I/O (64KB buffer)
- In-place sorting to minimize memory allocation
- Efficient string operations

## Security

LogStriker implements security best practices:
- Uses SSH key authentication (no password storage)
- Properly escapes all file paths to prevent command injection
- Uses subprocess argument lists (not shell=True)
- Handles encoding errors gracefully
- No credentials stored in code

## Troubleshooting

### Connection Issues
```
[!] Failed to connect to 'prod-teamserver'

Troubleshooting:
  1. Check SSH config file (~/.ssh/config)
  2. Verify host entry exists
  3. Test connection: ssh prod-teamserver
```

**Solution**: Verify SSH config entry and test manual connection

### Logs Directory Not Found
```
[-] Default path not found: /opt/tools/cobaltstrike/server/logs
[*] Searching for Cobalt Strike logs directory...
[-] Could not locate logs directory automatically

    Please enter the full path to the logs directory:
```

**Solution**: Enter the full path to your Cobalt Strike logs directory

### Empty Output Files
If output files contain no entries, check:
1. Date folders exist in logs directory
2. Beacon logs exist within IP folders
3. No download/parsing errors in output
4. Logs are not in an unexpected format

## Architecture

LogStriker consists of five main components:

1. **SSHManager**: Handles SSH connections and remote file operations
2. **LogDiscovery**: Finds and inventories Cobalt Strike logs
3. **LogParser**: Parses beacon and system logs into structured entries
4. **LogAggregator**: Combines and sorts entries chronologically
5. **LogWriter**: Writes aggregated logs to output files

For detailed architecture information, see `ARCHITECTURE.md`.

## Development

### Running Tests
```bash
# No automated tests currently - contributions welcome!
```

### Contributing
Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

MIT License - see LICENSE file for details

## Author

Part of the HackAndBackpack toolkit

## Version

1.0.0 - Initial release

## Changelog

### v1.0.0 (2025-01-01)
- Initial release
- Support for Cobalt Strike beacon log aggregation
- Chronological ordering by IP address
- System log consolidation
- Multi-line output preservation
- Remote teamserver access via SSH

## Related Tools

- **Cobalt Strike**: Commercial penetration testing framework
- **CSTC**: Cobalt Strike Toolchain - community extensions
- **SharPersist**: Persistence toolkit often used with Cobalt Strike

## Support

For issues, questions, or feature requests, please open an issue on GitHub:
https://github.com/hackandbackpack/logstriker/issues
