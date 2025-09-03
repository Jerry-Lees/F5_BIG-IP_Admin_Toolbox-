# F5 Token Lister

A Python script for listing and analyzing authentication tokens on F5 BIG-IP devices via REST API.

## Overview

The F5 Token Lister connects to F5 BIG-IP devices and retrieves information about all active authentication tokens. This is useful for:

- **Token Management**: View all active tokens on your F5 device
- **User Analysis**: See which users have active tokens and how many
- **Security Auditing**: Identify expired tokens that may not have been properly cleaned up
- **Troubleshooting**: Debug authentication issues and token accumulation problems

## Features

- **Complete Token Listing**: Shows all active tokens with detailed information
- **User Filtering**: Filter tokens to show only those belonging to a specific user
- **Token Details**: Displays token ID, username, creation time, expiration, and status
- **Expired Token Detection**: Automatically identifies and flags expired tokens
- **Summary Statistics**: Shows total token counts and expired token warnings
- **Debug Mode**: Provides detailed timestamp parsing information for troubleshooting

## Requirements

- Python 3.6+
- `requests` library
- `urllib3` library

Install dependencies:
```bash
pip install requests urllib3
```

## Usage

### Basic Syntax
```bash
./list-tokens.py --addr <F5_IP> --user <username> --pass <password> [options]
```

### Command Line Options

| Option | Required | Description |
|--------|----------|-------------|
| `--addr` | Yes | F5 device IP address or hostname |
| `--user` | Yes | Username for F5 device authentication |
| `--pass` | Yes | Password for F5 device authentication |
| `--port` | No | Port number (default: 443) |
| `--searchuser` | No | Filter tokens by specific username |
| `--debug` | No | Enable debug output for timestamp parsing |

### Examples

**List all tokens on the device:**
```bash
./list-tokens.py --addr 192.168.1.100 --user admin --pass mypassword
```

**Filter tokens for a specific user:**
```bash
./list-tokens.py --addr 192.168.1.100 --user admin --pass mypassword --searchuser testuser
```

**Use custom port:**
```bash
./list-tokens.py --addr f5.example.com --user admin --pass mypassword --port 8443
```

**Enable debug mode:**
```bash
./list-tokens.py --addr 192.168.1.100 --user admin --pass mypassword --debug
```

**Search for your own admin tokens:**
```bash
./list-tokens.py --addr 192.168.1.100 --user admin --pass mypassword --searchuser admin
```

## Sample Output

### All Tokens
```
F5 Networks Token Lister
========================================
Connecting to: 192.168.1.100:443
Username: admin

Authenticating to 192.168.1.100...
Authentication successful!
Retrieving token list...

Found 25 token(s) on 192.168.1.100
================================================================================

Token #1
----------------------------------------
Token ID: ABC123XYZ789EXAMPLE
Username: admin
Created: 2025-09-03 14:30:15
Last Update: 2025-09-03 14:35:22.123456
Timeout (sec): 1200
Expires: 2025-09-03 14:50:15
User Reference: N/A

...

================================================================================
Total tokens found: 25
⚠️  WARNING: 3 token(s) appear to be expired
```

### Filtered by User
```
F5 Networks Token Lister
========================================
Connecting to: 192.168.1.100:443
Username: admin
Search user: testuser

Authenticating to 192.168.1.100...
Authentication successful!
Retrieving token list...

Found 25 token(s) on 192.168.1.100
================================================================================
Searching for username: testuser
Tokens matching 'testuser': 5
Total tokens on device: 25
----------------------------------------

Token #1
----------------------------------------
Token ID: DEF456ABC123EXAMPLE
Username: testuser
Created: 2025-09-03 15:20:10
Last Update: 2025-09-03 15:25:33.987654
Timeout (sec): 1200
Expires: 2025-09-03 15:40:10
User Reference: N/A

...

================================================================================
Tokens shown for 'testuser': 5
Total tokens on device: 25
⚠️  WARNING: 1 token(s) appear to be expired for user 'testuser'
⚠️  Device total: 3 expired tokens across all users
```

### User Not Found
```
F5 Networks Token Lister
========================================
Connecting to: 192.168.1.100:443
Username: admin
Search user: nonexistent

Found 25 token(s) on 192.168.1.100
================================================================================
Searching for username: nonexistent
Tokens matching 'nonexistent': 0
Total tokens on device: 25
----------------------------------------

No tokens found for username 'nonexistent'
Available usernames in token list:
  • admin: 20 tokens
  • testuser: 5 tokens
```

## Token Information Displayed

For each token, the script shows:

- **Token ID**: The unique identifier for the token (truncated for security)
- **Username**: The user account that owns the token
- **Created**: When the token was created (parsed from F5 timestamps)
- **Last Update**: The most recent activity timestamp for the token
- **Timeout (sec)**: The token's timeout value in seconds
- **Expires**: Calculated expiration time based on creation + timeout
- **User Reference**: F5 internal reference link (typically N/A)
- **Status**: Flags expired tokens with ⚠️ warnings

## Authentication

The script authenticates to F5 devices by:

1. **Creating an authentication token** via POST to `/mgmt/shared/authn/login`
2. **Using that token** for subsequent API requests with `X-F5-Auth-Token` header

**Note**: The script will create one authentication token on the F5 device for its own use.

## Error Handling

- **401 Authentication Failed**: Check username/password and F5 device accessibility
- **Connection Errors**: Verify IP address, port, and network connectivity  
- **SSL Certificate Warnings**: Automatically disabled for self-signed certificates
- **Token Parsing Issues**: Use `--debug` flag to see raw timestamp values

## Security Considerations

- **Credentials**: Never hardcode passwords in scripts or commit them to version control
- **Network Security**: Use this tool only on trusted networks
- **Token Creation**: The script creates one authentication token that will appear in token lists
- **Access Logging**: F5 devices will log authentication attempts and API access

## Troubleshooting

### Debug Mode
Use `--debug` to see detailed timestamp parsing information:
```bash
./list-tokens.py --addr 192.168.1.100 --user admin --pass mypassword --debug
```

### Common Issues

**Authentication Failures:**
- Verify username and password are correct
- Check if the user account has REST API access permissions
- Ensure the F5 device is accessible on the specified port

**No Tokens Found:**
- This is normal for freshly configured F5 devices
- Tokens are created when users authenticate via GUI, API, or other methods

**Expired Tokens:**
- F5 should automatically clean up expired tokens
- Large numbers of expired tokens may indicate a cleanup issue
- Consider the purpose of your token analysis when seeing expired tokens

## License

This script is provided as-is for network administration and security analysis purposes. No guarantees of it's usability are made by the author. This script is also not affiliated or officially supported by F5 Networks.


