import boto3
import botocore
import os
import json
import time
import datetime
from threading import Lock
from botocore.exceptions import ClientError

class LogTransferManager:
    def __init__(self, session):
        self.session = session
        self.transfer_state = None
        self.lock = Lock()
        self.stop_requested = False  # Flag to signal stop
        self.is_running = False
        
        print("Log Transfer Manager initialized")
    
    def start_transfer(self, account_id, trail_name, destination, from_date=None, to_date=None, progress_callback=None):
        """Start transferring logs from a CloudTrail trail to a destination"""
        self.stop_requested = False
        self.is_running = True
        
        try:
            # Get CloudTrail client
            cloudtrail = self.session.client('cloudtrail')
            
            # Get trail details to find the S3 bucket
            trail_details = None
            
            try:
                # Try to get trail details
                response = cloudtrail.describe_trails(trailNameList=[trail_name])
                if response['trailList']:
                    trail_details = response['trailList'][0]
            except Exception as e:
                print(f"Error getting trail details: {str(e)}")
                raise Exception(f"Failed to get details for trail {trail_name}: {str(e)}")
            
            if not trail_details:
                raise Exception(f"Trail {trail_name} not found")
            
            # Get S3 bucket info
            bucket_name = trail_details.get('S3BucketName')
            prefix = trail_details.get('S3KeyPrefix', '')
            
            if not bucket_name:
                raise Exception("Trail does not have an S3 bucket configured")
            
            # Update progress
            if progress_callback:
                progress_callback(0, 0, f"Scanning CloudTrail logs in bucket {bucket_name}...")
            
            # Create S3 client
            s3 = self.session.client('s3')
            
            # Build the prefix for CloudTrail logs
            # Format: [prefix]/AWSLogs/[account_id]/CloudTrail/[region]/YYYY/MM/DD/
            if prefix:
                base_prefix = f"{prefix}/AWSLogs/"
            else:
                base_prefix = "AWSLogs/"
                
            # Support for organizational trails
            if trail_details.get('IsOrganizationTrail', False):
                # For org trails, we need to check logs from all accounts
                org_prefix = f"{base_prefix}"
            else:
                # For account-specific trails
                org_prefix = f"{base_prefix}{account_id}/CloudTrail/"
            
            # Find all matching log files
            log_files = []
            
            # Parse date range if provided
            start_date = None
            end_date = None
            
            if from_date:
                try:
                    start_date = datetime.datetime.strptime(from_date, "%Y-%m-%d")
                except ValueError:
                    raise Exception(f"Invalid from_date format: {from_date}. Use YYYY-MM-DD")
            
            if to_date:
                try:
                    end_date = datetime.datetime.strptime(to_date, "%Y-%m-%d")
                    # Set to end of day
                    end_date = end_date.replace(hour=23, minute=59, second=59)
                except ValueError:
                    raise Exception(f"Invalid to_date format: {to_date}. Use YYYY-MM-DD")
            
            # If no dates provided, default to last 7 days
            if not start_date:
                end_date = datetime.datetime.now()
                start_date = end_date - datetime.timedelta(days=7)
            
            if not end_date:
                end_date = datetime.datetime.now()
            
            # Update progress
            if progress_callback:
                progress_callback(0, 0, f"Scanning logs from {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}...")
            
            # Get all objects matching the date range
            paginator = s3.get_paginator('list_objects_v2')
            
            # Keep track of total files scanned
            scanned = 0
            
            for page in paginator.paginate(Bucket=bucket_name, Prefix=org_prefix):
                # Check if stop requested
                if self.stop_requested:
                    raise Exception("Log transfer stopped by user")
                
                if 'Contents' in page:
                    for obj in page['Contents']:
                        key = obj['Key']
                        
                        # Only process CloudTrail log files
                        if not key.endswith('.json.gz'):
                            continue
                            
                        # Make sure it's actually a CloudTrail log file
                        if '/CloudTrail/' not in key:
                            continue
                        
                        # Extract the date from the object key if possible
                        try:
                            # CloudTrail paths often contain the date in the format:
                            # .../CloudTrail/region/YYYY/MM/DD/...
                            parts = key.split('/')
                            # Find where the region, YYYY, MM, DD parts are
                            for i, part in enumerate(parts):
                                if part == "CloudTrail" and i+4 < len(parts):
                                    region = parts[i+1]
                                    year = int(parts[i+2])
                                    month = int(parts[i+3])
                                    day = int(parts[i+4])
                                    
                                    # Create datetime object
                                    file_date = datetime.datetime(year, month, day)
                                    
                                    # Check if within date range
                                    if start_date <= file_date <= end_date:
                                        log_files.append({
                                            'key': key, 
                                            'size': obj['Size'],
                                            'date': file_date,
                                            'last_modified': obj['LastModified']
                                        })
                                    break
                        except Exception as date_err:
                            # If we can't parse the date, include the file anyway
                            print(f"Warning: Could not parse date from {key}: {str(date_err)}")
                            log_files.append({
                                'key': key, 
                                'size': obj['Size'],
                                'last_modified': obj['LastModified']
                            })
                
                # Update scanning progress occasionally
                scanned += len(page.get('Contents', []))
                if progress_callback and scanned % 1000 == 0:
                    progress_callback(0, 0, f"Scanning logs: {scanned} files examined...")
            
            # Sort log files by date if available
            log_files.sort(key=lambda x: x.get('date', x.get('last_modified', 0)))
            
            # Create destination directory if it doesn't exist
            os.makedirs(destination, exist_ok=True)
            
            # Save the transfer state for potential resume
            self.transfer_state = {
                'account_id': account_id,
                'trail_name': trail_name,
                'bucket_name': bucket_name,
                'destination': destination,
                'from_date': from_date,
                'to_date': to_date,
                'total_logs': len(log_files),
                'transferred_logs': 0,
                'remaining_logs': log_files,
                'completed_logs': [],
                'completed': False
            }
            
            # Save state to file
            self._save_transfer_state(destination)
            
            # Start the actual download
            return self._download_logs(s3, log_files, destination, progress_callback)
        
        except Exception as e:
            self.is_running = False
            raise e
    
    def resume_transfer(self, progress_callback=None):
        """Resume a previously started transfer"""
        if not self.transfer_state:
            raise Exception("No transfer to resume")
        
        self.stop_requested = False
        self.is_running = True
        
        try:
            # Get transfer state values
            bucket_name = self.transfer_state.get('bucket_name')
            destination = self.transfer_state.get('destination')
            remaining_logs = self.transfer_state.get('remaining_logs', [])
            
            if not bucket_name or not destination or not remaining_logs:
                raise Exception("Invalid transfer state for resuming")
            
            # Create S3 client
            s3 = self.session.client('s3')
            
            # Get the current progress
            total_logs = self.transfer_state.get('total_logs', len(remaining_logs))
            transferred_logs = self.transfer_state.get('transferred_logs', 0)
            
            # Update progress
            if progress_callback:
                progress_callback(transferred_logs, total_logs, 
                                 f"Resuming transfer: {transferred_logs} of {total_logs} already transferred")
            
            # Continue the download
            return self._download_logs(s3, remaining_logs, destination, progress_callback, 
                                      transferred_logs, total_logs)
        
        except Exception as e:
            self.is_running = False
            raise e
    
    def _download_logs(self, s3, log_files, destination, progress_callback=None, 
                      initial_transferred=0, total_logs=None):
        """Download log files from S3 to the destination"""
        if total_logs is None:
            total_logs = len(log_files)
        
        transferred = initial_transferred
        completed_logs = []
        
        try:
            # Ensure the destination exists
            os.makedirs(destination, exist_ok=True)
            
            # Download each log file
            for i, log_file in enumerate(log_files):
                # Check if stop requested
                if self.stop_requested:
                    # Save state before stopping
                    self.transfer_state['remaining_logs'] = log_files[i:]
                    self.transfer_state['completed_logs'].extend(completed_logs)
                    self.transfer_state['transferred_logs'] = transferred
                    self._save_transfer_state(destination)
                    
                    raise Exception("Log transfer stopped by user")
                
                key = log_file['key']
                
                # Create subdirectories for the log files to match S3 structure
                if '/' in key:
                    # Extract the relative path (after AWSLogs)
                    try:
                        relative_path = key.split('AWSLogs/')[1]
                        target_dir = os.path.join(destination, os.path.dirname(relative_path))
                    except:
                        # If we can't extract a clean path, use a sanitized version of the key
                        sanitized_key = key.replace(':', '_').replace('$', '_')
                        target_dir = os.path.join(destination, os.path.dirname(sanitized_key))
                else:
                    target_dir = destination
                
                # Ensure target directory exists
                os.makedirs(target_dir, exist_ok=True)
                
                # Construct the target file path
                target_file = os.path.join(target_dir, os.path.basename(key))
                
                # Download the file
                try:
                    s3.download_file(
                        Bucket=self.transfer_state['bucket_name'],
                        Key=key,
                        Filename=target_file
                    )
                    
                    # Track completed file
                    completed_logs.append(log_file)
                    
                except Exception as download_err:
                    print(f"Error downloading {key}: {str(download_err)}")
                    # Continue with next file
                
                # Update progress
                transferred += 1
                if progress_callback:
                    progress_callback(transferred, total_logs)
                
                # Update and save state periodically
                if transferred % 10 == 0:
                    self.transfer_state['remaining_logs'] = log_files[i+1:]
                    self.transfer_state['completed_logs'].extend(completed_logs)
                    self.transfer_state['transferred_logs'] = transferred
                    completed_logs = []  # Reset after adding to state
                    self._save_transfer_state(destination)
            
            # Mark transfer as complete
            self.transfer_state['completed'] = True
            self.transfer_state['transferred_logs'] = total_logs
            self.transfer_state['remaining_logs'] = []
            self.transfer_state['completed_logs'].extend(completed_logs)
            self._save_transfer_state(destination)
            
            self.is_running = False
            return total_logs, transferred
        
        except Exception as e:
            if not self.stop_requested:
                # Only save state on error if not explicitly stopped
                self.transfer_state['remaining_logs'] = log_files[i:]
                self.transfer_state['completed_logs'].extend(completed_logs)
                self.transfer_state['transferred_logs'] = transferred
                self._save_transfer_state(destination)
            
            self.is_running = False
            raise e
    
    def _save_transfer_state(self, destination):
        """Save the current transfer state to a file in the destination directory"""
        if not self.transfer_state:
            return
        
        state_file = os.path.join(destination, ".transfer_state.json")
        
        try:
            with open(state_file, 'w') as f:
                # Convert datetime objects to strings for JSON serialization
                state_copy = dict(self.transfer_state)
                
                # Process remaining_logs
                for log in state_copy.get('remaining_logs', []):
                    if 'date' in log and isinstance(log['date'], datetime.datetime):
                        log['date'] = log['date'].isoformat()
                    if 'last_modified' in log and hasattr(log['last_modified'], 'isoformat'):
                        log['last_modified'] = log['last_modified'].isoformat()
                
                # Process completed_logs
                for log in state_copy.get('completed_logs', []):
                    if 'date' in log and isinstance(log['date'], datetime.datetime):
                        log['date'] = log['date'].isoformat()
                    if 'last_modified' in log and hasattr(log['last_modified'], 'isoformat'):
                        log['last_modified'] = log['last_modified'].isoformat()
                
                json.dump(state_copy, f, indent=2)
        except Exception as e:
            print(f"Warning: Failed to save transfer state: {str(e)}")
    
    def stop_transfer(self):
        """Request to stop the current transfer"""
        self.stop_requested = True
    
    def can_resume(self):
        """Check if there's a transfer that can be resumed"""
        return (self.transfer_state is not None and 
                not self.transfer_state.get('completed', False) and
                self.transfer_state.get('remaining_logs', []))
    
    def _is_current_account(self, account_id):
        """Check if the account ID is the current account"""
        sts_client = self.session.client('sts')
        current_account = sts_client.get_caller_identity()
        return current_account["Account"] == account_id
    
    def _assume_role_in_account(self, account_id):
        """Assume a role in another account and return a new session"""
        sts_client = self.session.client('sts')
        role_arn = f"arn:aws:iam::{account_id}:role/OrganizationAccountAccessRole"
        
        try:
            assumed_role = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName="CloudTrailLogExplorerSession"
            )
            
            # Create a new session with the assumed role credentials
            return boto3.Session(
                aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
                aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
                aws_session_token=assumed_role['Credentials']['SessionToken'],
                region_name=self.session.region_name
            )
        
        except botocore.exceptions.ClientError as e:
            raise Exception(f"Failed to assume role in account {account_id}: {str(e)}") 