import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import os
import datetime
import json
from aws_auth import AWSAuthManager
from aws_discovery import AWSDiscoveryManager
from log_transfer import LogTransferManager

class CloudTrailLogExplorerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("AWS CloudTrail Log Explorer")
        self.root.geometry("900x600")
        
        self.auth_manager = AWSAuthManager()
        self.discovery_manager = None
        self.transfer_manager = None
        self.active_transfer_manager = None  # Track the currently active transfer manager
        self.available_roles = []
        self.role_access_results = {}
        
        self.setup_ui()
    
    def setup_ui(self):
        # Main notebook (tabbed interface)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.setup_auth_tab()
        self.setup_roles_tab()
        self.setup_accounts_tab()
        self.setup_transfer_tab()
    
    def setup_auth_tab(self):
        auth_frame = ttk.Frame(self.notebook)
        self.notebook.add(auth_frame, text="AWS Authentication")
        
        # Auth method selection
        ttk.Label(auth_frame, text="Authentication Method:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=10)
        
        self.auth_method = tk.StringVar(value="profile")
        ttk.Radiobutton(auth_frame, text="AWS Profile", variable=self.auth_method, value="profile", 
                        command=self.toggle_auth_method).grid(row=0, column=1, sticky=tk.W)
        ttk.Radiobutton(auth_frame, text="API Keys", variable=self.auth_method, value="api_key", 
                        command=self.toggle_auth_method).grid(row=0, column=2, sticky=tk.W)
        
        # Profile selection
        ttk.Label(auth_frame, text="AWS Profile:").grid(row=1, column=0, sticky=tk.W, padx=10, pady=10)
        
        self.profile_var = tk.StringVar()
        self.profile_dropdown = ttk.Combobox(auth_frame, textvariable=self.profile_var, state="readonly")
        self.profile_dropdown.grid(row=1, column=1, sticky=tk.W+tk.E, padx=10, pady=10, columnspan=2)
        
        # API Key inputs
        ttk.Label(auth_frame, text="Access Key ID:").grid(row=2, column=0, sticky=tk.W, padx=10, pady=10)
        self.access_key_entry = ttk.Entry(auth_frame, width=40)
        self.access_key_entry.grid(row=2, column=1, sticky=tk.W+tk.E, padx=10, pady=10, columnspan=2)
        self.access_key_entry.config(state=tk.DISABLED)
        
        ttk.Label(auth_frame, text="Secret Access Key:").grid(row=3, column=0, sticky=tk.W, padx=10, pady=10)
        self.secret_key_entry = ttk.Entry(auth_frame, width=40, show="*")
        self.secret_key_entry.grid(row=3, column=1, sticky=tk.W+tk.E, padx=10, pady=10, columnspan=2)
        self.secret_key_entry.config(state=tk.DISABLED)
        
        # Region selection
        ttk.Label(auth_frame, text="AWS Region:").grid(row=4, column=0, sticky=tk.W, padx=10, pady=10)
        
        self.region_var = tk.StringVar(value="us-east-1")
        self.region_dropdown = ttk.Combobox(auth_frame, textvariable=self.region_var, state="readonly")
        self.region_dropdown.grid(row=4, column=1, sticky=tk.W+tk.E, padx=10, pady=10, columnspan=2)
        
        # Connect button
        self.connect_button = ttk.Button(auth_frame, text="Connect to AWS", command=self.connect_to_aws)
        self.connect_button.grid(row=5, column=0, columnspan=3, pady=20)
        
        # Status label
        self.status_label = ttk.Label(auth_frame, text="")
        self.status_label.grid(row=6, column=0, columnspan=3, pady=10)
        
        # Load profiles and regions
        self.load_aws_profiles()
        self.load_aws_regions()
    
    def setup_roles_tab(self):
        """Set up the Roles & Access tab for checking role permissions"""
        roles_frame = ttk.Frame(self.notebook)
        self.notebook.add(roles_frame, text="Roles & Access")
        
        # Top section with buttons
        button_frame = ttk.Frame(roles_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.discover_roles_button = ttk.Button(button_frame, text="Discover Available Roles", 
                                               command=self.discover_roles)
        self.discover_roles_button.pack(side=tk.LEFT, padx=5)
        
        self.test_role_access_button = ttk.Button(button_frame, text="Test Role Access", 
                                                command=self.test_role_access)
        self.test_role_access_button.pack(side=tk.LEFT, padx=5)
        self.test_role_access_button.config(state=tk.DISABLED)
        
        # Role selection button
        self.use_selected_role_button = ttk.Button(button_frame, text="Use Selected Role", 
                                               command=self.use_selected_role)
        self.use_selected_role_button.pack(side=tk.LEFT, padx=5)
        self.use_selected_role_button.config(state=tk.DISABLED)
        
        # Role list with colored status
        frame_top = ttk.LabelFrame(roles_frame, text="Available Roles")
        frame_top.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create a treeview for roles and their access
        columns = ("role_arn", "cloudtrail_access", "s3_access", "status")
        self.roles_tree = ttk.Treeview(frame_top, columns=columns, show="headings")
        
        # Define headings
        self.roles_tree.heading("role_arn", text="Role ARN")
        self.roles_tree.heading("cloudtrail_access", text="CloudTrail Access")
        self.roles_tree.heading("s3_access", text="S3 Access")
        self.roles_tree.heading("status", text="Status")
        
        # Define columns
        self.roles_tree.column("role_arn", width=300)
        self.roles_tree.column("cloudtrail_access", width=120)
        self.roles_tree.column("s3_access", width=120)
        self.roles_tree.column("status", width=100)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(frame_top, orient="vertical", command=self.roles_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.roles_tree.configure(yscrollcommand=scrollbar.set)
        self.roles_tree.pack(fill=tk.BOTH, expand=True)
        
        # Bind selection event to enable/disable use button
        self.roles_tree.bind("<<TreeviewSelect>>", self.on_role_selected)
        
        # Status and info section
        self.roles_status_label = ttk.Label(roles_frame, text="")
        self.roles_status_label.pack(pady=10)
        
        # Configure tags/colors
        self.roles_tree.tag_configure("full_access", foreground="green")
        self.roles_tree.tag_configure("partial_access", foreground="blue")
        self.roles_tree.tag_configure("no_access", foreground="red")
        self.roles_tree.tag_configure("error", foreground="red")
        self.roles_tree.tag_configure("not_tested", foreground="gray")
    
    def setup_accounts_tab(self):
        accounts_frame = ttk.Frame(self.notebook)
        self.notebook.add(accounts_frame, text="AWS Accounts & Trails")
        
        # Create a treeview for accounts and trails
        self.accounts_tree = ttk.Treeview(accounts_frame, columns=("account_id", "account_name", "trails_status"))
        self.accounts_tree.heading("#0", text="")
        self.accounts_tree.heading("account_id", text="Account ID")
        self.accounts_tree.heading("account_name", text="Account Name")
        self.accounts_tree.heading("trails_status", text="Trails Status")
        
        self.accounts_tree.column("#0", width=50)
        self.accounts_tree.column("account_id", width=120)
        self.accounts_tree.column("account_name", width=200)
        self.accounts_tree.column("trails_status", width=150)
        
        self.accounts_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(accounts_frame, orient="vertical", command=self.accounts_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.accounts_tree.configure(yscrollcommand=scrollbar.set)
        
        # Refresh button
        refresh_button = ttk.Button(accounts_frame, text="Refresh Accounts & Trails", 
                                    command=self.discover_accounts_and_trails)
        refresh_button.pack(pady=10)
        
        # Add binding for selecting a trail
        self.accounts_tree.bind("<<TreeviewSelect>>", self.on_trail_selected)
    
    def setup_transfer_tab(self):
        transfer_frame = ttk.Frame(self.notebook)
        self.notebook.add(transfer_frame, text="Log Transfer")
        
        # Selected trail info
        ttk.Label(transfer_frame, text="Selected Trail:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=10)
        self.selected_trail_label = ttk.Label(transfer_frame, text="No trail selected")
        self.selected_trail_label.grid(row=0, column=1, sticky=tk.W, padx=10, pady=10)
        
        # Destination selection
        ttk.Label(transfer_frame, text="Destination:").grid(row=1, column=0, sticky=tk.W, padx=10, pady=10)
        
        self.destination_frame = ttk.Frame(transfer_frame)
        self.destination_frame.grid(row=1, column=1, sticky=tk.W, padx=10, pady=10)
        
        self.destination_path = tk.StringVar()
        ttk.Entry(self.destination_frame, textvariable=self.destination_path, width=40).pack(side=tk.LEFT)
        ttk.Button(self.destination_frame, text="Browse...", command=self.select_destination).pack(side=tk.LEFT, padx=5)
        
        # Date range for logs
        ttk.Label(transfer_frame, text="Date Range:").grid(row=2, column=0, sticky=tk.W, padx=10, pady=10)
        
        date_frame = ttk.Frame(transfer_frame)
        date_frame.grid(row=2, column=1, sticky=tk.W, padx=10, pady=10)
        
        ttk.Label(date_frame, text="From:").pack(side=tk.LEFT)
        self.from_date_entry = ttk.Entry(date_frame, width=12)
        self.from_date_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(date_frame, text="To:").pack(side=tk.LEFT, padx=5)
        self.to_date_entry = ttk.Entry(date_frame, width=12)
        self.to_date_entry.pack(side=tk.LEFT, padx=5)
        
        # Set default dates (last 7 days)
        today = datetime.datetime.now()
        week_ago = today - datetime.timedelta(days=7)
        self.from_date_entry.insert(0, week_ago.strftime("%Y-%m-%d"))
        self.to_date_entry.insert(0, today.strftime("%Y-%m-%d"))
        
        # Transfer buttons
        button_frame = ttk.Frame(transfer_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)
        
        self.start_transfer_button = ttk.Button(button_frame, text="Start Transfer", 
                                               command=self.start_transfer)
        self.start_transfer_button.pack(side=tk.LEFT, padx=5)
        self.start_transfer_button.config(state=tk.DISABLED)
        
        self.resume_transfer_button = ttk.Button(button_frame, text="Resume Transfer", 
                                                command=self.resume_transfer)
        self.resume_transfer_button.pack(side=tk.LEFT, padx=5)
        self.resume_transfer_button.config(state=tk.DISABLED)
        
        # Add stop transfer button
        self.stop_transfer_button = ttk.Button(button_frame, text="Stop Transfer", 
                                             command=self.stop_transfer)
        self.stop_transfer_button.pack(side=tk.LEFT, padx=5)
        self.stop_transfer_button.config(state=tk.DISABLED)
        
        # Progress bar
        ttk.Label(transfer_frame, text="Progress:").grid(row=4, column=0, sticky=tk.W, padx=10, pady=10)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(transfer_frame, orient=tk.HORIZONTAL, length=400, 
                                            mode='determinate', variable=self.progress_var)
        self.progress_bar.grid(row=4, column=1, sticky=tk.W+tk.E, padx=10, pady=10)
        
        # Transfer status
        self.transfer_status_label = ttk.Label(transfer_frame, text="")
        self.transfer_status_label.grid(row=5, column=0, columnspan=2, pady=10)
    
    def load_aws_profiles(self):
        profiles = self.auth_manager.get_available_profiles()
        self.profile_dropdown['values'] = profiles
        if profiles:
            self.profile_var.set(profiles[0])  # Select the first profile by default
    
    def load_aws_regions(self):
        regions = self.auth_manager.get_available_regions()
        self.region_dropdown['values'] = regions
        self.region_var.set("us-east-1")  # Default to us-east-1
    
    def toggle_auth_method(self):
        if self.auth_method.get() == "profile":
            self.profile_dropdown.config(state="readonly")
            self.access_key_entry.config(state=tk.DISABLED)
            self.secret_key_entry.config(state=tk.DISABLED)
        else:
            self.profile_dropdown.config(state=tk.DISABLED)
            self.access_key_entry.config(state=tk.NORMAL)
            self.secret_key_entry.config(state=tk.NORMAL)
    
    def connect_to_aws(self):
        self.status_label.config(text="Connecting to AWS...")
        self.root.update()
        
        try:
            if self.auth_method.get() == "profile":
                profile = self.profile_var.get()
                region = self.region_var.get()
                self.auth_manager.authenticate_with_profile(profile, region)
            else:
                access_key = self.access_key_entry.get()
                secret_key = self.secret_key_entry.get()
                region = self.region_var.get()
                
                if not access_key or not secret_key:
                    messagebox.showerror("Authentication Error", 
                                         "Please enter both Access Key ID and Secret Access Key")
                    self.status_label.config(text="")
                    return
                
                self.auth_manager.authenticate_with_keys(access_key, secret_key, region)
            
            self.discovery_manager = AWSDiscoveryManager(self.auth_manager.session)
            self.transfer_manager = LogTransferManager(self.auth_manager.session)
            
            self.status_label.config(text="Successfully connected to AWS")
            
            # Enable the discover roles button
            self.discover_roles_button.config(state=tk.NORMAL)
            
            # Switch to roles tab to encourage role discovery first
            self.notebook.select(1)  # Roles tab is now at index 1
            
            # Prompt user to discover roles
            messagebox.showinfo("Connection Successful", "Connected to AWS. You can now discover available roles.")
            
        except Exception as e:
            messagebox.showerror("Authentication Error", str(e))
            self.status_label.config(text=f"Error: {str(e)}")
    
    def discover_roles(self):
        """Discover IAM roles that can be assumed with the current credentials"""
        if not self.auth_manager or not self.auth_manager.session:
            messagebox.showerror("Error", "Please connect to AWS first")
            return
        
        # Clear existing roles
        for item in self.roles_tree.get_children():
            self.roles_tree.delete(item)
        
        self.roles_status_label.config(text="Discovering available roles...")
        self.root.update()
        
        # Start discovery in a separate thread
        threading.Thread(target=self._perform_role_discovery, daemon=True).start()
    
    def _perform_role_discovery(self):
        """Background thread for role discovery"""
        try:
            # Get available roles using the auth manager
            self.available_roles = self.auth_manager.discover_available_roles()
            
            # Update the UI with discovered roles
            def update_roles_ui():
                # Clear any existing items
                for item in self.roles_tree.get_children():
                    self.roles_tree.delete(item)
                
                # Add roles to the tree
                for role in self.available_roles:
                    self.roles_tree.insert("", tk.END, 
                                          values=(role, "Not tested", "Not tested", "Not tested"))
                
                # Update status
                if self.available_roles:
                    self.roles_status_label.config(
                        text=f"Discovered {len(self.available_roles)} roles. Select 'Test Role Access' to check permissions."
                    )
                    self.test_role_access_button.config(state=tk.NORMAL)
                else:
                    self.roles_status_label.config(
                        text="No roles found that can be assumed with current credentials."
                    )
                    self.test_role_access_button.config(state=tk.DISABLED)
            
            # Schedule UI update on main thread
            self.root.after(0, update_roles_ui)
            
        except Exception as e:
            self.root.after(0, lambda: self.roles_status_label.config(text=f"Error discovering roles: {str(e)}"))
            self.root.after(0, lambda: messagebox.showerror("Role Discovery Error", str(e)))
    
    def test_role_access(self):
        """Test each role's access to CloudTrail and S3"""
        if not self.available_roles:
            messagebox.showerror("Error", "No roles available to test")
            return
        
        self.roles_status_label.config(text="Testing role access...")
        self.test_role_access_button.config(state=tk.DISABLED)
        self.root.update()
        
        # Start testing in a separate thread
        threading.Thread(target=self._perform_role_access_test, daemon=True).start()
    
    def _perform_role_access_test(self):
        """Background thread for testing role access"""
        try:
            # Reset results
            self.role_access_results = {}
            
            # Test each role
            for i, role_arn in enumerate(self.available_roles):
                # Update status
                curr_role_arn = role_arn  # Make a copy for lambda capture
                curr_index = i
                total = len(self.available_roles)
                
                self.root.after(0, lambda: self.roles_status_label.config(
                    text=f"Testing role {curr_index+1}/{total}: {curr_role_arn}"
                ))
                
                # Find the tree item for this role
                item_to_update = None
                for item in self.roles_tree.get_children():
                    if self.roles_tree.item(item, "values")[0] == curr_role_arn:
                        item_to_update = item
                        break
                
                if item_to_update:
                    # Update to show testing in progress - using a function to avoid lambda capture issues
                    def update_testing_status(item, role):
                        self.roles_tree.item(item, values=(role, "Testing...", "Testing...", "In progress"))
                    
                    self.root.after(0, lambda i=item_to_update, r=curr_role_arn: update_testing_status(i, r))
                
                # Try to assume the role
                try:
                    # Assume the role
                    session = self.auth_manager.assume_role(curr_role_arn)
                    
                    # Test CloudTrail access
                    cloudtrail_access = self.discovery_manager.test_cloudtrail_access(session)
                    
                    # Test S3 access for CloudTrail logs
                    s3_access = self.discovery_manager.test_s3_access_for_cloudtrail(session)
                    
                    # Store results
                    self.role_access_results[curr_role_arn] = {
                        "cloudtrail_access": cloudtrail_access,
                        "s3_access": s3_access
                    }
                    
                    # Determine status and color tag
                    if cloudtrail_access and s3_access:
                        status = "Full Access"
                        tag = "full_access"  # Green
                    elif cloudtrail_access:
                        status = "Partial Access"
                        tag = "partial_access"  # Blue
                    else:
                        status = "No Access"
                        tag = "no_access"  # Red
                    
                    # Update tree with results - using a function to avoid lambda capture issues
                    def update_results(item, role, cloudtrail, s3, status_text, tag_name):
                        self.roles_tree.item(
                            item, 
                            values=(role, "Yes" if cloudtrail else "No", "Yes" if s3 else "No", status_text),
                            tags=(tag_name,)
                        )
                    
                    # Schedule the update on the main thread
                    if item_to_update:
                        self.root.after(
                            0, 
                            lambda i=item_to_update, r=curr_role_arn, ct=cloudtrail_access, s3=s3_access, 
                                   st=status, tg=tag: update_results(i, r, ct, s3, st, tg)
                        )
                    
                except Exception as role_err:
                    # Role assumption failed
                    error_msg = str(role_err)
                    self.role_access_results[curr_role_arn] = {
                        "cloudtrail_access": False,
                        "s3_access": False,
                        "error": error_msg
                    }
                    
                    # Update tree with failure - using a function to avoid lambda capture issues
                    def update_error(item, role, error_text):
                        self.roles_tree.item(
                            item, 
                            values=(role, "No", "No", "Error"),
                            tags=("error",)
                        )
                    
                    # Schedule the update on the main thread
                    if item_to_update:
                        self.root.after(
                            0, 
                            lambda i=item_to_update, r=curr_role_arn, e=error_msg: update_error(i, r, e)
                        )
            
            # Update final status
            def final_status_update():
                self.roles_status_label.config(
                    text=f"Completed testing {len(self.available_roles)} roles. "
                         f"Green = Full Access, Blue = Partial Access, Red = No Access"
                )
                self.test_role_access_button.config(state=tk.NORMAL)
                
                # If we have roles with access, tell the user they can select them
                has_access_roles = any(
                    access.get("cloudtrail_access", False) 
                    for access in self.role_access_results.values()
                )
                
                if has_access_roles:
                    messagebox.showinfo(
                        "Testing Complete", 
                        "Role testing complete. You can now select a role with access (green or blue) "
                        "and click 'Use Selected Role' to proceed to trail discovery."
                    )
            
            self.root.after(0, final_status_update)
            
        except Exception as e:
            self.root.after(0, lambda: self.roles_status_label.config(text=f"Error testing roles: {str(e)}"))
            self.root.after(0, lambda: messagebox.showerror("Role Testing Error", str(e)))
            self.root.after(0, lambda: self.test_role_access_button.config(state=tk.NORMAL))
    
    def discover_accounts_and_trails(self):
        if not self.discovery_manager:
            messagebox.showerror("Error", "Please connect to AWS first")
            return
        
        # Clear existing items
        for item in self.accounts_tree.get_children():
            self.accounts_tree.delete(item)
        
        try:
            # Initial discovery status
            status_node = self.accounts_tree.insert("", tk.END, text="⏳", values=("Discovering...", "", ""))
            self.root.update()
            
            # Update status in the main window too
            self.status_label.config(text="Starting AWS account discovery...")
            
            # Display using role info if applicable
            if hasattr(self, 'selected_role_arn'):
                self.status_label.config(text=f"Starting AWS account discovery using role: {self.selected_role_arn}")
            
            self.root.update()
            
            # Start discovery in a separate thread to avoid freezing the UI
            threading.Thread(target=self._perform_discovery, args=(status_node,), daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("Discovery Error", str(e))
    
    def _perform_discovery(self, status_node):
        try:
            # Update status
            print("Starting AWS account discovery...")
            self.root.after(0, lambda: self.status_label.config(text="Discovering AWS accounts..."))
            self.root.after(0, lambda: self.accounts_tree.item(status_node, values=("Discovering AWS accounts...", "", "")))
            
            # Collect all discovery data first
            discovery_data = []
            org_trails = []
            org_trail_accounts = set()
            
            # First, discover all accounts
            accounts = self.discovery_manager.discover_accounts()
            print(f"Found {len(accounts)} AWS accounts")
            
            self.root.after(0, lambda: self.status_label.config(text=f"Found {len(accounts)} AWS accounts. Discovering CloudTrail configurations..."))
            self.root.after(0, lambda: self.accounts_tree.item(status_node, values=(f"Found {len(accounts)} accounts", "Discovering trails...", "")))
            
            # Then find all organizational trails
            for i, account in enumerate(accounts):
                account_id = account["AccountId"]
                account_name = account.get("Name", "Unknown")
                
                # Update status for each account
                print(f"[{i+1}/{len(accounts)}] Examining account {account_id} ({account_name})...")
                self.root.after(0, lambda aid=account_id, an=account_name, i=i, total=len(accounts): 
                    self.status_label.config(text=f"Checking account {aid} ({an})... [{i+1}/{total}]"))
                self.root.after(0, lambda aid=account_id, i=i, total=len(accounts): 
                    self.accounts_tree.item(status_node, values=(f"Checking account {aid}", f"Progress: {i+1}/{total}", "")))
                
                trails = self.discovery_manager.discover_trails(account_id)
                
                print(f"  - Found {len(trails)} trails for account {account_id}")
                
                # Store organizational trails
                for trail in trails:
                    if trail.get("IsOrganizationTrail", False):
                        print(f"  - Found organizational trail: {trail['Name']} in account {account_id}")
                        org_trails.append({
                            "owner_account_id": account_id,
                            "trail_name": trail["Name"],
                            "trail_data": trail
                        })
                        # This trail covers all accounts in the organization
                        org_trail_accounts.add(account_id)
            
            print(f"Found {len(org_trails)} organizational trails")
            
            # Update status before processing data
            self.root.after(0, lambda: self.status_label.config(text="Processing CloudTrail data..."))
            self.root.after(0, lambda: self.accounts_tree.item(status_node, values=("Processing data", "", "")))
            
            # Now process each account with the knowledge of organizational trails
            for account in accounts:
                account_id = account["AccountId"]
                account_name = account.get("Name", "Unknown")
                
                account_data = {
                    "account_id": account_id,
                    "account_name": account_name,
                    "trails": [],
                    "covered_by_org_trail": False,
                    "org_trail_details": []
                }
                
                # Add regular trails for this account
                trails = self.discovery_manager.discover_trails(account_id)
                account_data["trails"] = trails
                
                # Check if this account is covered by an organizational trail
                if org_trails:
                    # All accounts in the organization are covered by org trails
                    account_data["covered_by_org_trail"] = True
                    account_data["org_trail_details"] = org_trails
                
                discovery_data.append(account_data)
            
            # Clear status node now that we're ready to show real data
            self.root.after(0, lambda: self.accounts_tree.delete(status_node))
            self.root.after(0, lambda: self.status_label.config(text=f"Found {len(accounts)} accounts with {len(org_trails)} organizational trails"))
            
            # Now update the UI with the collected data
            def update_ui():
                for account_data in discovery_data:
                    account_id = account_data["account_id"]
                    account_name = account_data["account_name"]
                    trails = account_data["trails"]
                    covered_by_org_trail = account_data["covered_by_org_trail"]
                    org_trail_details = account_data["org_trail_details"]
                    
                    # Determine the status message
                    if trails:
                        status_message = f"{len(trails)} trails found"
                    elif covered_by_org_trail:
                        status_message = "Covered by Org Trail"
                    else:
                        status_message = "NO TRAILS"
                    
                    # Add account as a parent node
                    account_node = self.accounts_tree.insert("", tk.END, text="📁", 
                                                          values=(account_id, account_name, status_message))
                    
                    # Configure colors based on trail status
                    if not trails and not covered_by_org_trail:
                        # No trails and not covered by org trail - show in red
                        self.accounts_tree.item(account_node, tags=("no_trails",))
                        self.accounts_tree.tag_configure("no_trails", foreground="red")
                    elif covered_by_org_trail and not trails:
                        # Covered by org trail but no own trails - show in light green
                        self.accounts_tree.item(account_node, tags=("covered_by_org",))
                        self.accounts_tree.tag_configure("covered_by_org", foreground="#008800")
                    
                    # Add trails for this account
                    for trail in trails:
                        trail_name = trail["Name"]
                        storage_location = trail.get("S3BucketName", "Unknown")
                        is_org_trail = trail.get("IsOrganizationTrail", False)
                        
                        if is_org_trail:
                            # Mark organizational trails in bright green
                            trail_node = self.accounts_tree.insert(account_node, tk.END, text="🟢", 
                                                               values=(trail_name, "Org Trail", storage_location))
                            self.accounts_tree.item(trail_node, tags=("org_trail",))
                            self.accounts_tree.tag_configure("org_trail", foreground="#00AA00")
                        else:
                            self.accounts_tree.insert(account_node, tk.END, text="📊", 
                                                  values=(trail_name, "Account Trail", storage_location))
                    
                    # If this account is covered by an organizational trail but doesn't own it
                    # show which org trails cover it
                    if covered_by_org_trail and account_id not in org_trail_accounts:
                        for org_trail in org_trail_details:
                            if org_trail["owner_account_id"] != account_id:
                                owner_id = org_trail["owner_account_id"]
                                trail_name = org_trail["trail_name"]
                                trail_data = org_trail["trail_data"]
                                storage = trail_data.get("S3BucketName", "Unknown")
                                
                                reference_node = self.accounts_tree.insert(
                                    account_node, tk.END, text="🔄", 
                                    values=(f"{trail_name}", f"Org Trail (from {owner_id})", storage)
                                )
                                self.accounts_tree.item(reference_node, tags=("org_trail_ref",))
                                self.accounts_tree.tag_configure("org_trail_ref", foreground="#0088AA")
            
            # Expand all account nodes initially
            for item in self.accounts_tree.get_children():
                self.accounts_tree.item(item, open=True)
        
            # Schedule the UI update on the main thread
            self.root.after(0, update_ui)
            
            # Final status update after UI is populated
            self.status_label.config(text=f"Discovery complete: {len(accounts)} accounts, {sum(len(a['trails']) for a in discovery_data)} trails")
            
        except Exception as e:
            print(f"ERROR during discovery: {str(e)}")
            self.root.after(0, lambda: self.status_label.config(text=f"Error: {str(e)}"))
            self.root.after(0, lambda: messagebox.showerror("Discovery Error", str(e)))
    
    def on_trail_selected(self, event):
        selected_items = self.accounts_tree.selection()
        if not selected_items:
            return
        
        item = selected_items[0]
        parent = self.accounts_tree.parent(item)
        
        if parent:  # This is a trail, not an account
            trail_name = self.accounts_tree.item(item, "values")[0]
            account_id = self.accounts_tree.item(parent, "values")[0]
            storage_location = self.accounts_tree.item(item, "values")[2]
            
            self.selected_trail_info = {
                "account_id": account_id,
                "trail_name": trail_name,
                "storage_location": storage_location
            }
            
            self.selected_trail_label.config(text=f"{trail_name} (Account: {account_id})")
            self.notebook.select(2)  # Switch to transfer tab
            
            # Enable the transfer button
            self.start_transfer_button.config(state=tk.NORMAL)
    
    def select_destination(self):
        """Open a file dialog to select a destination directory for log transfer"""
        directory = filedialog.askdirectory(title="Select Destination Directory for Logs")
        if directory:  # If user didn't cancel
            self.destination_path.set(directory)
            # Check for a resume file when destination is selected
            self.check_for_resume_file()

    def check_for_resume_file(self):
        """Check if there's a transfer state file in the selected destination directory"""
        destination = self.destination_path.get()
        if not destination or not os.path.isdir(destination):
            return False
        
        # Check for a transfer state file
        state_file = os.path.join(destination, ".transfer_state.json")
        if os.path.exists(state_file):
            try:
                with open(state_file, 'r') as f:
                    transfer_state = json.load(f)
                
                # Check if the transfer is incomplete
                if (not transfer_state.get("completed", False) and 
                        transfer_state.get("transferred_logs", 0) < transfer_state.get("total_logs", 0)):
                    
                    # Store the state in the transfer manager
                    if not hasattr(self, 'transfer_manager') or self.transfer_manager is None:
                        self.transfer_manager = LogTransferManager(self.session)
                    
                    self.transfer_manager.transfer_state = transfer_state
                    
                    # Update the UI to show resumable transfer info
                    self.resume_transfer_button.config(state=tk.NORMAL)
                    transferred = transfer_state.get('transferred_logs', 0) 
                    total = transfer_state.get('total_logs', 0)
                    percent = (transferred / total * 100) if total > 0 else 0
                    
                    # Update progress bar
                    self.progress_var.set(percent)
                    
                    # Update status label
                    self.transfer_status_label.config(
                        text=f"Found incomplete transfer: {transferred} of {total} logs ({percent:.1f}%). You can resume."
                    )
                    
                    # Pre-fill the form with data from the saved state
                    trail_name = transfer_state.get('trail_name', '')
                    account_id = transfer_state.get('account_id', '')
                    if trail_name and account_id:
                        self.selected_trail_label.config(text=f"{trail_name} (Account: {account_id})")
                    
                    return True
            except Exception as e:
                print(f"Error reading transfer state file: {str(e)}")
        
        # No valid resume file found
        self.resume_transfer_button.config(state=tk.DISABLED)
        return False

    def start_transfer(self):
        """Start transferring logs from selected trail to destination"""
        # Don't allow starting a new transfer if one is already running
        if self.active_transfer_manager and self.active_transfer_manager.is_running:
            messagebox.showerror("Transfer in Progress", 
                               "A transfer is already in progress. Please stop it first.")
            return
            
        if not hasattr(self, 'selected_trail_info'):
            messagebox.showerror("Error", "Please select a trail first")
            return
        
        destination = self.destination_path.get()
        if not destination:
            messagebox.showerror("Error", "Please select a destination directory")
            return
        
        # Check for a resume file first
        if self.check_for_resume_file():
            # Ask the user if they want to resume or start a new transfer
            if messagebox.askyesno("Resume Found", 
                                 "An incomplete transfer was found. Do you want to resume it instead?\n\n"
                                 "Click Yes to resume the previous transfer.\n"
                                 "Click No to start a new transfer (this will overwrite the previous one)."):
                self.resume_transfer()
                return
        
        # Find the best role for this transfer if we have tested roles
        best_role = None
        if hasattr(self, 'role_access_results') and self.role_access_results:
            for role_arn, access_info in self.role_access_results.items():
                if access_info.get('cloudtrail_access') and access_info.get('s3_access'):
                    best_role = role_arn
                    break
        
        # If no role with full access was found, ask the user if they want to proceed with current credentials
        if not best_role and self.role_access_results:
            # Check if we have any roles with partial access
            partial_access_role = None
            for role_arn, access_info in self.role_access_results.items():
                if access_info.get('cloudtrail_access'):
                    partial_access_role = role_arn
                    break
            
            if partial_access_role:
                if not messagebox.askyesno("Limited Access", 
                                        "No role with full access to both CloudTrail and S3 was found.\n\n"
                                        "Some roles can list CloudTrail but can't download logs.\n"
                                        "Do you want to proceed using your current credentials?"):
                    return
            else:
                if not messagebox.askyesno("No Access", 
                                        "None of the tested roles have access to CloudTrail or S3.\n\n"
                                        "Do you want to proceed using your current credentials?"):
                    return
        
        # Continue with starting a new transfer...
        from_date = self.from_date_entry.get()
        to_date = self.to_date_entry.get()
        
        # Validate dates
        try:
            if from_date:
                datetime.datetime.strptime(from_date, "%Y-%m-%d")
            if to_date:
                datetime.datetime.strptime(to_date, "%Y-%m-%d")
        except ValueError:
            messagebox.showerror("Error", "Invalid date format. Use YYYY-MM-DD")
            return
        
        # Disable start and resume buttons, enable stop button
        self.start_transfer_button.config(state=tk.DISABLED)
        self.resume_transfer_button.config(state=tk.DISABLED)
        self.stop_transfer_button.config(state=tk.NORMAL)
        
        # Reset progress
        self.progress_var.set(0)
        self.transfer_status_label.config(text="Initializing transfer...")
        
        # Start transfer in a separate thread
        threading.Thread(
            target=self._perform_transfer,
            args=(self.selected_trail_info["account_id"], self.selected_trail_info["trail_name"], 
                  destination, from_date, to_date, best_role),
            daemon=True
        ).start()

    def resume_transfer(self):
        """Resume a previously started transfer"""
        # Don't allow resuming if a transfer is already running
        if self.active_transfer_manager and self.active_transfer_manager.is_running:
            messagebox.showerror("Transfer in Progress", 
                               "A transfer is already in progress. Please stop it first.")
            return
            
        destination = self.destination_path.get()
        if not destination:
            messagebox.showerror("Error", "Please select a destination directory")
            return
        
        # Check if we need to create/get the transfer manager
        if not hasattr(self, 'transfer_manager') or self.transfer_manager is None:
            self.transfer_manager = LogTransferManager(self.auth_manager.session)
        
        # Load the transfer state from file
        state_file = os.path.join(destination, ".transfer_state.json")
        if not os.path.exists(state_file):
            # Check if we've already identified a state file
            if hasattr(self, 'resume_file_path') and os.path.exists(self.resume_file_path):
                state_file = self.resume_file_path
            else:
                messagebox.showerror("Error", "No transfer available to resume")
                return
        
        # Load the state
        try:
            with open(state_file, 'r') as f:
                transfer_state = json.load(f)
            
            # Set the transfer state in the manager
            self.transfer_manager.transfer_state = transfer_state
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load transfer state: {str(e)}")
            return
        
        # Disable resume and start buttons, enable stop button
        self.resume_transfer_button.config(state=tk.DISABLED)
        self.start_transfer_button.config(state=tk.DISABLED)
        self.stop_transfer_button.config(state=tk.NORMAL)
        
        # Reset progress display
        self.transfer_status_label.config(text="Resuming transfer...")
        
        # Set the active transfer manager
        self.active_transfer_manager = self.transfer_manager
        
        # Start the resume in a separate thread
        threading.Thread(target=self._perform_resume_transfer, daemon=True).start()

    def _perform_transfer(self, account_id, trail_name, destination, from_date=None, to_date=None, role_arn=None):
        """Background thread for performing the transfer"""
        try:
            # Update status to show if using a role
            if role_arn:
                self.root.after(0, lambda: self.transfer_status_label.config(
                    text=f"Assuming role {role_arn} for transfer..."
                ))
                
                # Get a session with the role
                session = self.auth_manager.assume_role(role_arn)
                
                # Create a transfer manager with the role session
                transfer_manager = LogTransferManager(session)
            else:
                transfer_manager = self.transfer_manager
            
            # Set this as the active transfer manager
            self.active_transfer_manager = transfer_manager
            
            total, transferred = transfer_manager.start_transfer(
                account_id, trail_name, destination, from_date, to_date,
                progress_callback=self._update_progress
            )
            
            # Update UI after completion
            self.root.after(0, lambda: self._update_transfer_complete(total, transferred))
            
        except Exception as e:
            self.root.after(0, lambda: self._update_transfer_error(str(e)))
        finally:
            # Clear the active transfer manager reference when done
            if self.active_transfer_manager == transfer_manager:
                self.active_transfer_manager = None

    def _perform_resume_transfer(self):
        """Background thread for resuming the transfer"""
        try:
            total, transferred = self.active_transfer_manager.resume_transfer(
                progress_callback=self._update_progress
            )
            
            # Update UI after completion
            self.root.after(0, lambda: self._update_transfer_complete(total, transferred))
            
        except Exception as e:
            self.root.after(0, lambda: self._update_transfer_error(str(e)))
        finally:
            # Clear the active transfer manager reference when done
            self.active_transfer_manager = None

    def _update_progress(self, current, total, status_text=None):
        """Update transfer progress in the UI"""
        if status_text:
            self.root.after(0, lambda: self.transfer_status_label.config(text=status_text))
        
        if total > 0:
            progress = (current / total) * 100
            self.root.after(0, lambda: self.progress_var.set(progress))
            
            if not status_text:  # Only update if we didn't get a custom status text
                self.root.after(0, lambda: self.transfer_status_label.config(
                    text=f"Transferred {current} of {total} logs ({progress:.1f}%)"
                ))
        elif not status_text:  # If no total yet and no custom message
            self.root.after(0, lambda: self.transfer_status_label.config(
                text="Preparing transfer..."
            ))

    def _update_transfer_complete(self, total, transferred):
        """Update UI after transfer completion"""
        self.progress_var.set(100)
        self.transfer_status_label.config(
            text=f"Transfer complete! Transferred {transferred} of {total} logs."
        )
        self.start_transfer_button.config(state=tk.NORMAL)
        self.resume_transfer_button.config(state=tk.DISABLED)
        self.stop_transfer_button.config(state=tk.DISABLED)
        
        # Clear the active transfer manager
        self.active_transfer_manager = None

    def _update_transfer_error(self, error_message):
        """Update UI after transfer error"""
        # Check if this is a user-initiated stop
        if "stopped by user" in error_message.lower():
            self.transfer_status_label.config(text="Transfer stopped by user.")
        else:
            self.transfer_status_label.config(text=f"Error: {error_message}")
        
        self.start_transfer_button.config(state=tk.NORMAL)
        self.stop_transfer_button.config(state=tk.DISABLED)
        
        # Clear the active transfer manager
        self.active_transfer_manager = None
        
        # Enable resume button if we can resume
        if self.transfer_manager and self.transfer_manager.can_resume():
            self.resume_transfer_button.config(state=tk.NORMAL)
        else:
            self.resume_transfer_button.config(state=tk.DISABLED)

    def stop_transfer(self):
        """Stop the currently running transfer"""
        if not self.active_transfer_manager:
            # If no active transfer manager, try the main one as fallback
            if not self.transfer_manager:
                return
            else:
                # Use the main transfer manager as fallback
                manager_to_stop = self.transfer_manager
        else:
            # Use the active transfer manager
            manager_to_stop = self.active_transfer_manager
        
        # Confirm stop
        if messagebox.askyesno("Confirm Stop", "Are you sure you want to stop the transfer?"):
            # Stop the transfer
            manager_to_stop.stop_transfer()
            self.transfer_status_label.config(text="Stopping transfer... Please wait...")
            
            # Enable start button, disable stop and resume
            self.stop_transfer_button.config(state=tk.DISABLED)

    def on_role_selected(self, event):
        """Handle role selection in the roles tree"""
        selected_items = self.roles_tree.selection()
        if selected_items:
            item = selected_items[0]
            role_values = self.roles_tree.item(item, "values")
            role_arn = role_values[0]
            role_status = role_values[3]
            
            # Only enable the use button for roles with some level of access
            if role_status in ["Full Access", "Partial Access"]:
                self.use_selected_role_button.config(state=tk.NORMAL)
                self.selected_role_arn = role_arn
            else:
                self.use_selected_role_button.config(state=tk.DISABLED)
                if hasattr(self, 'selected_role_arn'):
                    delattr(self, 'selected_role_arn')
    
    def use_selected_role(self):
        """Use the selected role for discovering CloudTrail logs"""
        if not hasattr(self, 'selected_role_arn'):
            messagebox.showerror("Error", "Please select a role with access first")
            return
        
        # Try to assume the role
        try:
            # Get the role session
            role_session = self.auth_manager.assume_role(self.selected_role_arn)
            
            # Create a new discovery manager with this role's session
            self.discovery_manager = AWSDiscoveryManager(role_session)
            
            # Update UI to show we're using this role
            messagebox.showinfo("Role Selected", 
                               f"Now using role:\n{self.selected_role_arn}\n\nYou can proceed to the Accounts tab.")
            
            # Switch to the accounts tab
            self.notebook.select(2)  # 0-based index, accounts tab should be at position 2
            
        except Exception as e:
            messagebox.showerror("Role Error", f"Failed to use selected role: {str(e)}")