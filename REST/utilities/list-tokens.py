#!/usr/bin/env python3
"""
F5 Networks Token Lister Script
Lists all active tokens on an F5 BIG-IP device via REST API

Usage:
    python3 f5_token_lister.py --addr 192.168.1.100 --user admin --pass mypassword
    python3 f5_token_lister.py --addr f5.example.com --user admin --pass mypassword --debug
    python3 f5_token_lister.py --addr f5.example.com --user admin --pass mypassword --searchuser testuser
"""

import requests
import json
import sys
import argparse
from datetime import datetime, timedelta
import urllib3

# Disable SSL warnings for self-signed certificates (common with F5 devices)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class F5TokenLister:
    def __init__(self, host, username, password, port=443):
        self.host = host
        self.username = username 
        self.password = password
        self.port = port
        self.base_url = f"https://{host}:{port}/mgmt"
        self.session = requests.Session()
        self.session.verify = False

    def authenticate(self):
        """Authenticate with F5 device and get auth token"""
        auth_url = f"{self.base_url}/shared/authn/login"
        auth_data = {
            "username": self.username,
            "password": self.password,
            "loginProviderName": "tmos"
        }
        
        try:
            print(f"Authenticating to {self.host}...")
            response = self.session.post(auth_url, json=auth_data, timeout=10)
            response.raise_for_status()
            
            auth_response = response.json()
            self.auth_token = auth_response.get('token', {}).get('token')
            
            if not self.auth_token:
                raise Exception("Failed to obtain authentication token")
                
            # Set the token for future requests
            self.session.headers.update({'X-F5-Auth-Token': self.auth_token})
            print("Authentication successful!")
            return True
            
        except requests.exceptions.RequestException as e:
            print(f"Authentication failed: {e}")
            return False
        except Exception as e:
            print(f"Authentication error: {e}")
            return False

    def get_tokens(self):
        """Retrieve all tokens from F5 device"""
        tokens_url = f"{self.base_url}/shared/authz/tokens"
        
        try:
            print("Retrieving token list...")
            response = self.session.get(tokens_url, timeout=10)
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            print(f"Failed to retrieve tokens: {e}")
            return None

    def format_token_info(self, token):
        """Format token information for readable output"""
        token_id = token.get('token', 'N/A')
        username = token.get('userName', 'N/A')
        user_reference = token.get('userReference', {})
        
        # Extract timing information
        generation_time = token.get('generation', 0)
        timeout = token.get('timeout', 0)
        last_update = token.get('lastUpdateMicros', 0)
        
        # Debug output if requested
        if hasattr(self, 'debug') and self.debug:
            print(f"DEBUG - Token: {token_id[:8]}... Raw values: generation={generation_time}, timeout={timeout}, lastUpdate={last_update}")
        
        # Parse last update time (this typically works correctly)
        try:
            if last_update > 0:
                if last_update > 1e12:  # Microseconds since epoch
                    last_update_time = datetime.fromtimestamp(last_update / 1_000_000)
                else:  # Seconds since epoch
                    last_update_time = datetime.fromtimestamp(last_update)
            else:
                last_update_time = "Unknown"
        except Exception:
            last_update_time = "Unknown"

        # Try to parse creation time from generation field
        creation_time = "Unknown"
        expiration_time = "Unknown"
        
        if generation_time and generation_time != 0:
            try:
                # Try different timestamp formats
                if 1000000000 < generation_time < 2000000000:  # Unix timestamp in seconds
                    creation_time = datetime.fromtimestamp(generation_time)
                elif 1000000000000 < generation_time < 2000000000000:  # Milliseconds
                    creation_time = datetime.fromtimestamp(generation_time / 1000)
                elif generation_time > 1000000000000000:  # Microseconds
                    creation_time = datetime.fromtimestamp(generation_time / 1_000_000)
                
                # Calculate expiration if we have both creation time and timeout
                if isinstance(creation_time, datetime) and timeout > 0:
                    expiration_time = creation_time + timedelta(seconds=timeout)
                    
            except Exception:
                creation_time = "Unknown"
        
        # If we couldn't parse creation time but have last_update and timeout, estimate
        if creation_time == "Unknown" and isinstance(last_update_time, datetime) and timeout > 0:
            try:
                # Estimate creation as last_update minus timeout (rough approximation)
                creation_time = f"{last_update_time - timedelta(seconds=timeout)} (estimated)"
                expiration_time = f"{last_update_time} (estimated from last update)"
            except Exception:
                pass
            
        return {
            'token_id': token_id,
            'username': username,
            'creation_time': creation_time,
            'last_update': last_update_time,
            'timeout_seconds': timeout,
            'expiration_time': expiration_time,
            'user_reference_link': user_reference.get('link', 'N/A')
        }

    def list_tokens(self, filter_username=None):
        """Main method to list all tokens"""
        if not self.authenticate():
            return False
            
        tokens_data = self.get_tokens()
        if not tokens_data:
            return False
            
        tokens = tokens_data.get('items', [])
        
        if not tokens:
            print("\nNo tokens found on the device.")
            return True
            
        print(f"\nFound {len(tokens)} token(s) on {self.host}")
        print("=" * 80)
        
        # If filtering by username, separate the tokens first
        if filter_username:
            filtered_tokens = [token for token in tokens if token.get('userName', '').lower() == filter_username.lower()]
            print(f"Searching for username: {filter_username}")
            print(f"Tokens matching '{filter_username}': {len(filtered_tokens)}")
            print(f"Total tokens on device: {len(tokens)}")
            print("-" * 40)
            
            if not filtered_tokens:
                print(f"\nNo tokens found for username '{filter_username}'")
                print(f"Available usernames in token list:")
                usernames = set(token.get('userName', 'Unknown') for token in tokens)
                for username in sorted(usernames):
                    user_count = len([t for t in tokens if t.get('userName', '') == username])
                    print(f"  • {username}: {user_count} tokens")
                return True
            
            # Show filtered tokens
            tokens_to_show = filtered_tokens
            total_tokens = len(tokens)
        else:
            # Show all tokens
            tokens_to_show = tokens
            total_tokens = len(tokens)
        
        for i, token in enumerate(tokens_to_show, 1):
            formatted = self.format_token_info(token)
            
            print(f"\nToken #{i}")
            print("-" * 40)
            print(f"Token ID: {formatted['token_id']}")
            print(f"Username: {formatted['username']}")
            print(f"Created: {formatted['creation_time']}")
            print(f"Last Update: {formatted['last_update']}")
            print(f"Timeout (sec): {formatted['timeout_seconds']}")
            print(f"Expires: {formatted['expiration_time']}")
            print(f"User Reference: {formatted['user_reference_link']}")
            
            # Check if token appears to be expired
            expiry = formatted['expiration_time']
            if isinstance(expiry, datetime):
                if expiry < datetime.now():
                    print("⚠️  TOKEN APPEARS EXPIRED")
            elif isinstance(expiry, str) and "estimated" in expiry:
                try:
                    time_part = expiry.split("(estimated")[0].strip()
                    est_time = datetime.strptime(time_part.split(".")[0], "%Y-%m-%d %H:%M:%S")
                    if est_time < datetime.now():
                        print("⚠️  TOKEN APPEARS EXPIRED (estimated)")
                except Exception:
                    pass
                    
        print("\n" + "=" * 80)
        if filter_username:
            print(f"Tokens shown for '{filter_username}': {len(tokens_to_show)}")
            print(f"Total tokens on device: {total_tokens}")
        else:
            print(f"Total tokens found: {len(tokens_to_show)}")
        
        # Show summary of potentially problematic tokens
        if filter_username:
            # Count expired tokens in filtered set
            expired_count = 0
            for token in tokens_to_show:
                formatted = self.format_token_info(token)
                expiry = formatted['expiration_time']
                
                if isinstance(expiry, datetime):
                    if expiry < datetime.now():
                        expired_count += 1
                elif isinstance(expiry, str) and "estimated" in expiry:
                    try:
                        time_part = expiry.split("(estimated")[0].strip()
                        est_time = datetime.strptime(time_part.split(".")[0], "%Y-%m-%d %H:%M:%S")
                        if est_time < datetime.now():
                            expired_count += 1
                    except:
                        pass
                        
            if expired_count > 0:
                print(f"⚠️  WARNING: {expired_count} token(s) appear to be expired for user '{filter_username}'")
                
            # Also show total expired count for all tokens
            total_expired = 0
            for token in tokens:
                formatted = self.format_token_info(token)
                expiry = formatted['expiration_time']
                
                if isinstance(expiry, datetime):
                    if expiry < datetime.now():
                        total_expired += 1
                elif isinstance(expiry, str) and "estimated" in expiry:
                    try:
                        time_part = expiry.split("(estimated")[0].strip()
                        est_time = datetime.strptime(time_part.split(".")[0], "%Y-%m-%d %H:%M:%S")
                        if est_time < datetime.now():
                            total_expired += 1
                    except:
                        pass
            
            if total_expired > 0:
                print(f"⚠️  Device total: {total_expired} expired tokens across all users")
        else:
            # Original logic for showing expired tokens when not filtering
            expired_count = 0
            for token in tokens:
                formatted = self.format_token_info(token)
                expiry = formatted['expiration_time']
                
                if isinstance(expiry, datetime):
                    if expiry < datetime.now():
                        expired_count += 1
                elif isinstance(expiry, str) and "estimated" in expiry:
                    try:
                        time_part = expiry.split("(estimated")[0].strip()
                        est_time = datetime.strptime(time_part.split(".")[0], "%Y-%m-%d %H:%M:%S")
                        if est_time < datetime.now():
                            expired_count += 1
                    except:
                        pass
            
            if expired_count > 0:
                print(f"⚠️  WARNING: {expired_count} token(s) appear to be expired")
            
        return True

def main():
    parser = argparse.ArgumentParser(
        description="List all tokens on an F5 BIG-IP device",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --addr 192.168.1.100 --user admin --pass mypassword
  %(prog)s --addr f5.example.com --user admin --pass mypassword --debug
  %(prog)s --addr f5.example.com --user admin --pass mypassword --searchuser testuser
        """
    )
    
    parser.add_argument('--addr', required=True, 
                       help='F5 device IP address or hostname')
    parser.add_argument('--user', required=True,
                       help='Username for F5 device authentication')
    parser.add_argument('--pass', dest='password', required=True,
                       help='Password for F5 device authentication')
    parser.add_argument('--port', type=int, default=443,
                       help='Port number (default: 443)')
    parser.add_argument('--searchuser', dest='filter_username',
                       help='Filter tokens by specific username')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug output to troubleshoot timestamp parsing')
    
    args = parser.parse_args()
    
    print("F5 Networks Token Lister")
    print("=" * 40)
    print(f"Connecting to: {args.addr}:{args.port}")
    print(f"Username: {args.user}")
    if args.filter_username:
        print(f"Search user: {args.filter_username}")
    print()
        
    # Create and run token lister
    lister = F5TokenLister(args.addr, args.user, args.password, args.port)
    
    # Enable debug mode if requested
    if args.debug:
        lister.debug = True
        print("Debug mode enabled - will show raw timestamp values")
    
    try:
        success = lister.list_tokens(args.filter_username)
        if not success:
            print("Failed to retrieve token information.")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\nOperation cancelled.")
        sys.exit(0)
    except Exception as e:
        print(f"Unexpected error: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()

