#!/usr/bin/env python3
"""
F5 Networks Token Creator Script - Multi-threaded Edition
Creates authentication tokens repeatedly without using them
Useful for testing token accumulation behavior

⚠️  WARNING: DO NOT RUN THIS SCRIPT IN A PRODUCTION ENVIRONMENT! ⚠️
This script rapidly creates authentication tokens and may destabilize the F5 REST API.
Use only in test/development environments!

Usage:
    python3 f5_token_creator.py --addr 192.168.1.100 --user admin --pass mypassword
    python3 f5_token_creator.py --addr f5.example.com --user admin --pass mypassword --evil --threads 10
"""

import requests
import json
import sys
import argparse
import time
import random
import threading
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
import urllib3

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class F5TokenCreator:
    def __init__(self, host, username, password, port=443):
        self.host = host
        self.username = username 
        self.password = password
        self.port = port
        self.base_url = f"https://{host}:{port}/mgmt"
        self.tokens_created = []
        self.errors_encountered = []
        self.thread_stats = {}
        self.lock = threading.Lock()  # For thread-safe operations
        self.running = True

    def get_actual_token_count(self, retry_count=3):
        """Get the actual number of active tokens on the F5 device"""
        if hasattr(self, 'debug') and self.debug:
            print(f"DEBUG: Attempting to get actual token count from {self.host}")
        
        for attempt in range(retry_count):
            try:
                # Try basic auth first (like the lister script)
                session = requests.Session()
                session.verify = False
                session.auth = (self.username, self.password)
                
                tokens_url = f"{self.base_url}/shared/authz/tokens"
                if hasattr(self, 'debug') and self.debug:
                    print(f"DEBUG: Attempt {attempt + 1}: Trying basic auth to {tokens_url}")
                    
                response = session.get(tokens_url, timeout=10)
                
                if hasattr(self, 'debug') and self.debug:
                    print(f"DEBUG: Basic auth response status: {response.status_code}")
                
                if response.status_code == 200:
                    tokens_data = response.json()
                    count = len(tokens_data.get('items', []))
                    if hasattr(self, 'debug') and self.debug:
                        print(f"DEBUG: Successfully got token count via basic auth: {count}")
                    return count
                else:
                    if hasattr(self, 'debug') and self.debug:
                        print(f"DEBUG: Basic auth failed, trying token-based auth")
                    # If basic auth fails, try with a token we created
                    if self.tokens_created:
                        session.auth = None
                        session.headers.update({'X-F5-Auth-Token': self.tokens_created[-1]['token_id']})
                        response = session.get(tokens_url, timeout=10)
                        
                        if hasattr(self, 'debug') and self.debug:
                            print(f"DEBUG: Token auth response status: {response.status_code}")
                        
                        if response.status_code == 200:
                            tokens_data = response.json()
                            count = len(tokens_data.get('items', []))
                            if hasattr(self, 'debug') and self.debug:
                                print(f"DEBUG: Successfully got token count via token auth: {count}")
                            return count
                    
                    if hasattr(self, 'debug') and self.debug:
                        print(f"DEBUG: Both auth methods failed on attempt {attempt + 1}")
                
            except Exception as e:
                print(f"ERROR: Failed to get actual token count (attempt {attempt + 1}): {e}")
                if hasattr(self, 'debug') and self.debug:
                    import traceback
                    traceback.print_exc()
            
            # Wait a bit before retrying (except on last attempt)
            if attempt < retry_count - 1:
                time.sleep(0.5)
        
        return None  # All attempts failed

    def create_token(self, thread_id=0):
        """Create a new authentication token"""
        auth_url = f"{self.base_url}/shared/authn/login"
        auth_data = {
            "username": self.username,
            "password": self.password,
            "loginProviderName": "tmos"
        }
        
        try:
            session = requests.Session()
            session.verify = False
            
            response = session.post(auth_url, json=auth_data, timeout=10)
            
            if response.status_code == 200:
                auth_response = response.json()
                token_info = auth_response.get('token', {})
                token_id = token_info.get('token')
                
                if token_id:
                    # Thread-safe storage of token info
                    with self.lock:
                        self.tokens_created.append({
                            'token_id': token_id,
                            'created_at': datetime.now(),
                            'username': token_info.get('userName', self.username),
                            'timeout': token_info.get('timeout', 'unknown'),
                            'thread_id': thread_id
                        })
                        # Update thread stats
                        if thread_id not in self.thread_stats:
                            self.thread_stats[thread_id] = {'success': 0, 'failure': 0}
                        self.thread_stats[thread_id]['success'] += 1
                    return True, None
                else:
                    error_msg = "No token in response"
                    return False, error_msg
            else:
                error_msg = f"HTTP {response.status_code}"
                try:
                    # Try to get error details from response
                    error_response = response.json()
                    if 'message' in error_response:
                        error_msg += f": {error_response['message']}"
                except:
                    pass
                return False, error_msg
                
        except requests.exceptions.RequestException as e:
            return False, str(e)
        except Exception as e:
            return False, str(e)

    def worker_thread(self, thread_id, duration_seconds, show_output=True):
        """Worker function for each thread"""
        start_time = datetime.now()
        end_time = start_time + timedelta(seconds=duration_seconds)
        
        attempt_count = 0
        while datetime.now() < end_time and self.running:
            attempt_count += 1
            
            success, error_msg = self.create_token(thread_id)
            
            if show_output:
                timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
                if success:
                    token_id = self.tokens_created[-1]['token_id']
                    print(f"[{timestamp}] Thread {thread_id:2d} #{attempt_count:3d}: SUCCESS ({token_id[:8]}...)")
                else:
                    print(f"[{timestamp}] Thread {thread_id:2d} #{attempt_count:3d}: FAILED ({error_msg})")
            
            # Thread-safe error tracking
            if not success:
                with self.lock:
                    self.errors_encountered.append({
                        'thread_id': thread_id,
                        'attempt_number': attempt_count,
                        'timestamp': datetime.now(),
                        'error': error_msg
                    })
                    # Update thread stats
                    if thread_id not in self.thread_stats:
                        self.thread_stats[thread_id] = {'success': 0, 'failure': 0}
                    self.thread_stats[thread_id]['failure'] += 1

    def run_single_threaded(self, duration_seconds=60):
        """Single-threaded token creation (original behavior)"""
        print(f"Creating tokens on {self.host} (single-threaded) for {duration_seconds} seconds...")
        print("=" * 70)
        
        start_time = datetime.now()
        end_time = start_time + timedelta(seconds=duration_seconds)
        
        success_count = 0
        failure_count = 0
        attempt_number = 0
        
        while datetime.now() < end_time:
            attempt_number += 1
            remaining_time = (end_time - datetime.now()).total_seconds()
            
            print(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Token #{attempt_number}... ", end="", flush=True)
            
            success, error_msg = self.create_token(0)
            
            if success:
                success_count += 1
                token_id = self.tokens_created[-1]['token_id']
                print(f"SUCCESS (ID: {token_id[:12]}...)")
            else:
                failure_count += 1
                print(f"FAILED ({error_msg})")
                self.errors_encountered.append({
                    'thread_id': 0,
                    'attempt_number': attempt_number,
                    'timestamp': datetime.now(),
                    'error': error_msg
                })
            
            if attempt_number % 25 == 0 or remaining_time < 5:
                elapsed = (datetime.now() - start_time).total_seconds()
                rate = attempt_number / elapsed if elapsed > 0 else 0
                print(f"   Progress: {success_count} created, {failure_count} failed, {remaining_time:.1f}s left, {rate:.1f} attempts/sec")
        
        return self._print_summary(start_time, attempt_number)

    def run_multi_threaded(self, duration_seconds=60, num_threads=5):
        """Multi-threaded token creation"""
        print(f"🔥 EVIL MODE: Creating tokens on {self.host} with {num_threads} threads for {duration_seconds} seconds!")
        print("⚠️  WARNING: This is EXTREMELY aggressive and may bring down services!")
        print("=" * 80)
        
        start_time = datetime.now()
        
        # Create and start threads
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            # Submit all worker threads
            futures = []
            for thread_id in range(num_threads):
                future = executor.submit(self.worker_thread, thread_id, duration_seconds, num_threads <= 10)
                futures.append(future)
            
            # Wait for all threads to complete
            try:
                for future in futures:
                    future.result()
            except KeyboardInterrupt:
                print("\n🛑 Stopping all threads...")
                self.running = False
                # Wait a bit for threads to stop gracefully
                time.sleep(1)
        
        total_attempts = sum(self.thread_stats.get(tid, {}).get('success', 0) + 
                           self.thread_stats.get(tid, {}).get('failure', 0) 
                           for tid in range(num_threads))
        
        return self._print_summary(start_time, total_attempts, num_threads)

    def _print_summary(self, start_time, total_attempts, num_threads=1):
        """Print detailed summary of token creation session"""
        elapsed_total = (datetime.now() - start_time).total_seconds()
        success_count = len(self.tokens_created)
        failure_count = len(self.errors_encountered)
        
        print("\n" + "=" * 80)
        if num_threads > 1:
            print(f"🔥 EVIL MODE SESSION COMPLETED!")
        else:
            print("🏁 Token creation session completed!")
            
        print(f"Duration: {elapsed_total:.1f} seconds")
        print(f"Threads used: {num_threads}")
        print(f"Total attempts: {total_attempts}")
        print(f"Tokens successfully created: {success_count}")
        print(f"Failed attempts: {failure_count}")
        print(f"Success rate: {(success_count/total_attempts)*100:.1f}%" if total_attempts > 0 else "0%")
        print(f"Average rate: {total_attempts/elapsed_total:.1f} attempts/second")
        
        if num_threads > 1:
            tokens_per_second = success_count / elapsed_total
            print(f"Token creation rate: {tokens_per_second:.1f} tokens/second ({tokens_per_second*60:.1f} tokens/minute)")
        else:
            tokens_per_minute = success_count / (elapsed_total / 60)
            print(f"Token creation rate: {tokens_per_minute:.1f} tokens/minute")
        
        # Per-thread statistics for multi-threaded mode
        if num_threads > 1 and self.thread_stats:
            print(f"\n📊 PER-THREAD STATISTICS:")
            print("-" * 50)
            for thread_id in sorted(self.thread_stats.keys()):
                stats = self.thread_stats[thread_id]
                total = stats['success'] + stats['failure']
                success_rate = (stats['success'] / total * 100) if total > 0 else 0
                print(f"Thread {thread_id:2d}: {stats['success']:4d} success, {stats['failure']:4d} failed, {success_rate:5.1f}% success rate")
        
        # Error summary
        if self.errors_encountered:
            print(f"\n❌ ERROR SUMMARY ({len(self.errors_encountered)} errors):")
            print("-" * 60)
            
            # Group errors by type
            error_types = {}
            for error_info in self.errors_encountered:
                error_msg = error_info['error']
                if error_msg not in error_types:
                    error_types[error_msg] = []
                error_types[error_msg].append(error_info)
            
            for error_msg, error_list in error_types.items():
                print(f"• '{error_msg}': {len(error_list)} times")
                if num_threads > 1:
                    # Show which threads had this error
                    thread_counts = {}
                    for err in error_list:
                        tid = err['thread_id']
                        thread_counts[tid] = thread_counts.get(tid, 0) + 1
                    thread_summary = ", ".join([f"T{tid}({count})" for tid, count in sorted(thread_counts.items())])
                    print(f"  Threads: {thread_summary}")
            
            # Show timing of first and last errors
            first_error = min(self.errors_encountered, key=lambda x: x['timestamp'])
            last_error = max(self.errors_encountered, key=lambda x: x['timestamp'])
            print(f"\nFirst error: Thread {first_error['thread_id']} at {first_error['timestamp'].strftime('%H:%M:%S')}")
            print(f"Last error:  Thread {last_error['thread_id']} at {last_error['timestamp'].strftime('%H:%M:%S')}")
        else:
            print(f"\n✅ No errors encountered!")
        
        if success_count > 0:
            print(f"\n📋 TOKEN CREATION SUMMARY:")
            print("-" * 40)
            # Show first few tokens from each thread if multi-threaded
            if num_threads > 1:
                shown = 0
                for thread_id in range(num_threads):
                    thread_tokens = [t for t in self.tokens_created if t['thread_id'] == thread_id]
                    if thread_tokens and shown < 10:  # Show up to 10 total
                        token = thread_tokens[0]
                        print(f"T{thread_id}: {token['token_id'][:20]}... ({token['created_at'].strftime('%H:%M:%S')})")
                        shown += 1
                if success_count > 10:
                    print(f"... and {success_count - 10} more tokens")
            else:
                # Single threaded - show first 5
                for i, token_info in enumerate(self.tokens_created[:5], 1):
                    print(f"{i}. {token_info['token_id'][:20]}... ({token_info['created_at'].strftime('%H:%M:%S')})")
                if len(self.tokens_created) > 5:
                    print(f"... and {len(self.tokens_created) - 5} more tokens")
            
            # Get actual token count from the device
            print(f"\n📊 DEVICE TOKEN STATUS:")
            print("-" * 30)
            print(f"Tokens created this session: {success_count}")
            
            actual_count = self.get_actual_token_count()
            if actual_count is not None:
                print(f"⚠️  Total active tokens on {self.host}: {actual_count}")
                if actual_count > success_count:
                    existing_tokens = actual_count - success_count
                    print(f"   ({existing_tokens} tokens existed before this session)")
            else:
                print(f"❓ Could not retrieve current token count from {self.host}")
                print("   (Use the token lister script to see all active tokens)")
        
        return success_count

def main():
    # Parse arguments first to check for --evil
    parser = argparse.ArgumentParser(add_help=False)  # Disable help for initial parse
    parser.add_argument('--evil', action='store_true')
    parser.add_argument('--threads', type=int, default=5)
    known_args, _ = parser.parse_known_args()
    
    # Show warning first, even before parsing all arguments
    if len(sys.argv) == 1 or '--help' in sys.argv or '-h' in sys.argv:
        pass  # Let full argparse handle help
    else:
        # Show warnings based on mode
        if known_args.evil:
            print("💀" * 30)
            print("⚠️  EXTREME DANGER - EVIL MODE ENABLED ⚠️")
            print("💀" * 30)
            print()
            print("🔥 EVIL MODE WILL USE MULTIPLE THREADS TO HAMMER THE F5 DEVICE! 🔥")
            print()
            print("❌❌❌ ABSOLUTELY DO NOT RUN IN PRODUCTION! ❌❌❌")
            print()
            print("This EVIL mode creates tokens with multiple simultaneous threads and WILL:")
            print("• Almost certainly destabilize or crash the F5 REST API")
            print("• Consume massive amounts of memory and CPU resources") 
            print("• Cause widespread authentication failures for all users")
            print("• Trigger DDoS protection and security controls")
            print("• Potentially require a device reboot to recover")
            print()
            print(f"📊 EVIL MODE SETTINGS: {known_args.threads} threads running simultaneously")
            print()
            print("🚨 THIS IS THE NUCLEAR OPTION FOR TESTING ONLY! 🚨")
            print("💀" * 30)
            print()
        else:
            print("🚨" * 25)
            print("⚠️  CRITICAL WARNING - READ BEFORE PROCEEDING ⚠️")
            print("🚨" * 25)
            print()
            print("❌ DO NOT RUN THIS SCRIPT IN A PRODUCTION ENVIRONMENT! ❌")
            print()
            print("This script creates authentication tokens rapidly and may:")
            print("• Destabilize the F5 REST API")
            print("• Consume excessive memory and CPU resources") 
            print("• Cause authentication issues for other users")
            print("• Trigger rate limiting or security controls")
            print("• Leave numerous tokens that may not be cleaned up properly")
            print()
            print("✅ ONLY use this in test/development environments!")
            print("🚨" * 25)
            print()
        
        # Require explicit acknowledgment with randomized prompts
        try:
            # Randomize the case of each letter in "I UNDERSTAND" 
            phrase = "I UNDERSTAND THE RISKS" if known_args.evil else "I UNDERSTAND"
            randomized_phrase = ''.join(
                char.upper() if random.choice([True, False]) else char.lower() 
                for char in phrase
            )
            
            print(f"Type exactly: {randomized_phrase}")
            response1 = input("Enter the phrase: ").strip()
            if response1 != randomized_phrase:
                print("Incorrect phrase entered. Exiting.")
                sys.exit(0)
            
            # Generate random 6-digit number
            random_number = random.randint(100000, 999999)
            risk_message = "potentially bringing services down" if not known_args.evil else "almost certainly CRASHING the F5 device"
            print(f"\nTo be certain you want to take the risk of {risk_message},")
            print(f"enter the number below to verify:")
            print(f"{random_number}")
            response2 = input("Enter the number: ").strip()
            if response2 != str(random_number):
                print("Incorrect number entered. Exiting.")
                sys.exit(0)
                
            print("\n✅ Confirmation complete. Proceeding...")
            print()
        except KeyboardInterrupt:
            print("\nExiting.")
            sys.exit(0)

    # Full argument parsing
    parser = argparse.ArgumentParser(
        description="Create authentication tokens on an F5 BIG-IP device",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
⚠️  WARNING: This script may destabilize the F5 REST API - use only in test environments!

Examples:
  %(prog)s --addr 192.168.1.100 --user admin --pass mypassword
  %(prog)s --addr f5.example.com --user admin --pass mypassword --duration 120
  %(prog)s --addr f5.example.com --user admin --pass mypassword --evil --threads 10 --duration 30
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
    parser.add_argument('--duration', type=int, default=60,
                       help='Duration in seconds to create tokens (default: 60)')
    parser.add_argument('--evil', action='store_true',
                       help='Enable multi-threaded EVIL mode (DANGEROUS!)')
    parser.add_argument('--threads', type=int, default=5,
                       help='Number of threads for EVIL mode (default: 5, max: 20)')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug output')
    
    args = parser.parse_args()
    
    if args.duration < 1 or args.duration > 600:
        print("Duration must be between 1 and 600 seconds")
        sys.exit(1)
        
    if args.threads < 1 or args.threads > 20:
        print("Thread count must be between 1 and 20")
        sys.exit(1)
    
    # Removed the EVIL mode duration limit - user understands the risks
    
    mode = f"EVIL MODE ({args.threads} threads)" if args.evil else "Standard Mode"
    print(f"F5 Networks Token Creator - {mode}")
    print("=" * 50)
    print(f"Target device: {args.addr}:{args.port}")
    print(f"Username: {args.user}")
    print(f"Duration: {args.duration} seconds")
    if args.evil:
        print(f"Threads: {args.threads}")
    print()
    
    # Create and run token creator
    creator = F5TokenCreator(args.addr, args.user, args.password, args.port)
    
    if args.debug:
        creator.debug = True
        print("Debug mode enabled")
    
    try:
        if args.evil:
            tokens_created = creator.run_multi_threaded(args.duration, args.threads)
        else:
            tokens_created = creator.run_single_threaded(args.duration)
        
        if tokens_created > 0:
            print(f"\n✅ Successfully created {tokens_created} tokens!")
            if args.evil:
                print("🔥 EVIL MODE completed - check your F5 device status immediately!")
            else:
                print("⚠️  These tokens are now active on the F5 device.")
            print("   Run the token lister script to view all active tokens.")
        else:
            print("\n❌ No tokens were successfully created.")
            if creator.errors_encountered:
                print("   Check the error summary above for details.")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n\n⏹️  Operation cancelled by user.")
        if creator.tokens_created:
            print(f"Partial results: {len(creator.tokens_created)} tokens were created before cancellation.")
        if creator.errors_encountered:
            print(f"Errors encountered: {len(creator.errors_encountered)}")
        sys.exit(0)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()

