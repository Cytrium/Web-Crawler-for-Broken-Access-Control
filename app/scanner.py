# app/scanner.py
"""
Quick Scan Crawler and Security Testing Engine
Discovers URLs and tests for Broken Access Control vulnerabilities using Playwright.

Stages (high level):
1) Login -> create isolated contexts per role and authenticate.
2) Crawl -> discover URLs per role (GET-only, in-scope, non-destructive).
3) Retest -> union set tested across roles with fingerprints + denial signals.
4) Analyze -> compare roles to flag BAC detections 1..6.
5) Persist -> save URLs, violations, and report summary.

Role-Based Crawling Rules:
- No credentials: Crawl as Guest only
- Admin only: Crawl as Admin + Guest
- User only: Crawl as User + Guest
- Admin + User: Crawl as Admin + User + Guest

Each role crawls separately with isolated browser context.
URLs are compared across roles to detect BAC vulnerabilities.
"""

from urllib.parse import urljoin, urlparse, urlunparse, parse_qsl, urlencode
from datetime import datetime
from threading import Thread
import time
import os
import json
import re
import hashlib
import difflib
from collections import deque

# Global dictionary to track scan progress
scan_progress = {}


class QuickScanner:
    """
    Quick Scan scanner that crawls URLs using Playwright and tests for 
    Broken Access Control vulnerabilities across multiple user roles.
    
    Key Design Principles:
    - Crawl with EACH selected role separately
    - Guest always crawls (unauthenticated baseline)
    - Compare discovered URLs across roles to detect BAC
    - Fail gracefully if a role authentication fails
    - No batch processing, single target URL only
    """
    
    def __init__(self, scan_id, config, db, app):
        """
        Initialize the scanner with configuration.
        
        Args:
            scan_id: Database scan ID
            config: Dict containing scan configuration:
                - base_url: Target URL to scan
                - max_depth: Maximum crawl depth (default: 3)
                - max_pages: Maximum pages per role (default: 100)
                - auth_profiles: List of authentication profiles
                - check_bac: Enable broken access control testing
                - check_priv_escalation: Enable privilege escalation testing
                - check_session: Enable session management testing
                - capture_screenshots: Enable screenshot capture
            db: SQLAlchemy database instance
            app: Flask app instance for context
        """
        self.scan_id = scan_id
        self.config = config
        self.db = db
        self.app = app
        
        # Extract config
        self.base_url = config.get('base_url', '').rstrip('/')
        self.base_path = None  # Will be set after validation
        self.max_depth = config.get('max_depth', 3)
        self.max_pages = config.get('max_pages', 100)
        self.crawl_delay_ms = int(config.get('crawl_delay', 500))
        self.timeout_seconds = int(config.get('timeout', 30))
        self.timeout_ms = max(5000, self.timeout_seconds * 1000)
        
        # Authentication profiles from config
        # Each profile: {role_name, username, password, login_url, privilege_level}
        self.auth_profiles = config.get('auth_profiles', [])
        
        # Test options
        self.test_bac = config.get('check_bac', True)
        self.test_priv_esc = config.get('check_priv_escalation', True)
        self.test_session = config.get('check_session', True)
        self.test_forced_browsing = config.get('check_forced_browsing', True)
        self.test_auth_bypass = config.get('check_auth_bypass', True)
        self.capture_screenshots = config.get('capture_screenshots', False)
        self.debug_access_matrix = config.get('debug_access_matrix', False)
        self.spa_mode = config.get('spa_mode', False)

        # Target-specific settings (optional)
        # DVWA security levels: low, medium, high, impossible
        self.dvwa_security_level = (config.get('dvwa_security_level') or '').strip().lower() or None
        if self.dvwa_security_level not in (None, 'low', 'medium', 'high', 'impossible'):
            self.dvwa_security_level = None
        
        # Manual login options (for complex auth flows like CAPTCHA, 2FA, SSO)
        # Can be set via environment variables or config
        self.manual_login = config.get('manual_login', os.getenv("MANUAL_LOGIN", "0") == "1")
        self.login_wait_seconds = config.get('login_wait_seconds', int(os.getenv("LOGIN_WAIT_SECONDS", "120")))
        
        # State tracking - URLs discovered per role
        self.urls_by_role = {}  # {role_name: set(urls)}
        self.all_discovered_urls = set()
        self.violations = []
        self.auth_failures = []  # Track roles that failed to authenticate
        
        # Enhanced tracking for BAC detection and evidence
        # {url: {role: {status, final_url, redirect_chain, title, text_hash, text_len,
        #              text_excerpt, denial_signals, has_login_form, allowed_like, denied_like}}}
        self.url_data = {}
        self.violation_evidence = []
        
        # Roles to crawl (determined by input)
        self.roles_to_crawl = []
        
        # Playwright resources (lazy init)
        self.playwright = None
        self.browser = None
        self.role_contexts = {}  # {role_name: browser_context}
        
        # Initialize progress tracking
        self._init_progress_tracking()
    
    def _init_progress_tracking(self):
        """Initialize progress tracking for this scan."""
        global scan_progress
        scan_progress[self.scan_id] = {
            'status': 'Initializing',
            'stage': 'init',
            'current_activity': 'Starting scan...',
            'urls_discovered': 0,
            'urls_tested': 0,
            'violations_found': 0,
            'current_url': '',
            'current_role': '',
            'errors': [],
            'start_time': datetime.utcnow().isoformat(),
            'progress_percent': 0
        }
    
    def _get_base_path(self, url):
        """
        Extract the base path from a URL for scope enforcement.
        If URL points to a file (has extension), use parent directory.
        
        Examples:
        - http://localhost/DVWA -> /dvwa
        - http://localhost/DVWA/index.php -> /dvwa
        - http://localhost/ -> /
        """
        try:
            parsed = urlparse(url)
            path = parsed.path.rstrip('/')
            
            # If path ends with a file extension, get parent directory
            if path:
                last_segment = path.split('/')[-1]
                if '.' in last_segment:
                    path = '/'.join(path.split('/')[:-1])
            
            # Normalize to lowercase for comparison
            return path.lower() if path else '/'
        except:
            return '/'
    
    def _update_progress(self, **kwargs):
        """Update scan progress."""
        global scan_progress
        if self.scan_id in scan_progress:
            scan_progress[self.scan_id].update(kwargs)

    def _get_spa_seed_routes(self):
        return [
            '#/', '#/login', '#/register', '#/search', '#/about',
            '#/products', '#/basket', '#/orders', '#/order-history',
            '#/profile', '#/accounting', '#/administration',
            '#/privacy-security', '#/complain', '#/contact',
            '#/track-result', '#/score-board', '#/delivery-methods',
            '#/payment', '#/wallet', '#/address', '#/password',
            '#/forgot-password', '#/change-password'
        ]
    
    def _determine_roles_to_crawl(self):
        """
        Determine which roles to crawl based on provided credentials.
        
        Rules (MANDATORY):
        - No credentials → Guest only
        - Admin only → Admin + Guest
        - User only → User + Guest
        - Admin + User → Admin + User + Guest
        """
        has_admin = False
        has_user = False
        
        for profile in self.auth_profiles:
            role_name = profile.get('role_name', '').lower()
            if profile.get('username') and profile.get('password'):
                if role_name == 'admin':
                    has_admin = True
                else:
                    has_user = True
        
        # Build roles list based on credentials provided
        self.roles_to_crawl = []
        
        if has_admin:
            self.roles_to_crawl.append('admin')
        if has_user:
            self.roles_to_crawl.append('user')
        
        # Guest is ALWAYS included
        self.roles_to_crawl.append('guest')
        
        print(f"📋 Roles to crawl: {self.roles_to_crawl}")
        return self.roles_to_crawl
    
    def run(self):
        """
        Execute the Quick Scan workflow.
        
        Workflow:
        1. Validate configuration
        2. Determine roles to crawl based on input
        3. Initialize Playwright browser
        4. For each role:
            a. Create isolated browser context
            b. Authenticate (if not Guest)
            c. Crawl from base URL
            d. Store discovered URLs
        5. Compare URLs across roles
        6. Detect and record BAC violations
        7. Generate summary report
        
        Returns:
            Dict with success status and scan results
        """
        from app.models import Scan, URL, Violation, Report
        
        with self.app.app_context():
            try:
                # Update status to Running
                scan = Scan.query.get(self.scan_id)
                if not scan:
                    return {'success': False, 'message': 'Scan not found'}
                
                scan.status = 'Running'
                self.db.session.commit()
                
                # Step 1: Validate configuration
                self._update_progress(
                    status='Validating',
                    stage='validate',
                    current_activity='Validating scan configuration...',
                    progress_percent=2
                )
                validation_result = self._validate_config()
                if not validation_result['valid']:
                    raise ValueError(validation_result['message'])
                
                # Set base path after validation
                self.base_path = self._get_base_path(self.base_url)
                self.base_url = self._normalize_url(self.base_url) or self.base_url
                print(f"📍 Scope restricted to path: {self.base_path}")
                
                # Step 2: Determine roles to crawl
                self._update_progress(
                    status='Initializing',
                    stage='init',
                    current_activity='Determining roles to crawl...',
                    progress_percent=5
                )
                self._determine_roles_to_crawl()
                
                # Step 3: Initialize Playwright
                self._update_progress(
                    status='Initializing',
                    stage='init',
                    current_activity='Launching browser...',
                    progress_percent=8
                )
                self._init_playwright()
                
                # Step 4: Create contexts and authenticate
                total_roles = len(self.roles_to_crawl)
                for idx, role in enumerate(self.roles_to_crawl):
                    role_progress_start = 10 + (idx * 8)
                    self._update_progress(
                        status='Login',
                        stage='login',
                        current_activity=f'Creating {role} context...',
                        current_role=role,
                        progress_percent=role_progress_start
                    )
                    context = self._create_role_context(role)
                    if context is None and role != 'guest':
                        self.auth_failures.append(role)
                        print(f"Skipping {role} role - authentication failed")
                        continue
                    self.role_contexts[role] = context

                # Step 5: Crawl with each role
                for idx, role in enumerate(self.roles_to_crawl):
                    if role not in self.role_contexts:
                        continue
                    role_progress_start = 20 + (idx * 15)
                    self._update_progress(
                        status='Crawl',
                        stage='crawl',
                        current_activity=f'Crawling as {role.capitalize()}...',
                        current_role=role,
                        progress_percent=role_progress_start
                    )
                    self.urls_by_role[role] = set()
                    self._crawl_as_role(role, self.base_url, depth=0)
                    print(f"{role.capitalize()} discovered {len(self.urls_by_role[role])} URLs")
                    self.all_discovered_urls.update(self.urls_by_role[role])
                    self._update_progress(
                        urls_discovered=len(self.all_discovered_urls),
                        progress_percent=role_progress_start + 10
                    )

                # Step 6: Cross-role retest
                self._update_progress(
                    status='Retest',
                    stage='retest',
                    current_activity='Testing all URLs across all roles...',
                    progress_percent=70
                )
                self._cross_role_test()

                # Step 7: Persist discovered URLs (needed before violations)
                self._update_progress(
                    status='Save',
                    stage='save',
                    current_activity='Saving URLs...',
                    progress_percent=80
                )
                self._persist_urls()

                # Step 8: Compare URLs and detect BAC violations
                self._update_progress(
                    status='Analyze',
                    stage='analyze',
                    current_activity='Comparing access across roles...',
                    progress_percent=85
                )
                self._compare_and_detect_violations()

                # Additional security tests
                if self.test_session:
                    self._test_session_management()

                # Step 7: Finalize and generate report
                self._update_progress(
                    status='Finalizing',
                    stage='finalize',
                    current_activity='Generating report...',
                    progress_percent=95
                )
                
                # URLs already persisted before analysis

                scan.status = 'Completed'
                scan.end_time = datetime.utcnow()
                # Persist an accurate count based on what's in the DB for this scan.
                # This avoids any mismatch if in-memory violations diverge from persisted rows.
                try:
                    from app.models import Violation, URL as UrlModel
                    self.db.session.flush()
                    scan.vulnerable_count = (
                        self.db.session.query(Violation)
                        .join(UrlModel, Violation.url_id == UrlModel.url_id)
                        .filter(UrlModel.scan_id == self.scan_id)
                        .count()
                    )
                except Exception:
                    scan.vulnerable_count = len(self.violations)
                self.db.session.commit()
                
                # Generate report
                report = Report(
                    scan_id=self.scan_id,
                    generated_at=datetime.utcnow(),
                    summary=self._generate_summary()
                )
                self.db.session.add(report)
                self.db.session.commit()
                
                # Mark as complete
                self._update_progress(
                    status='Completed',
                    stage='complete',
                    current_activity='Scan complete!',
                    urls_tested=len(self.all_discovered_urls),
                    violations_found=len(self.violations),
                    progress_percent=100
                )
                
                return {
                    'success': True,
                    'urls_found': len(self.all_discovered_urls),
                    'violations_found': len(self.violations),
                    'roles_crawled': list(self.urls_by_role.keys()),
                    'auth_failures': self.auth_failures
                }
                
            except Exception as e:
                import traceback
                error_trace = traceback.format_exc()
                print(error_trace)
                
                # Update progress with error
                self._update_progress(
                    status='Failed',
                    stage='failed',
                    current_activity=f'Error: {str(e)}',
                    progress_percent=0
                )
                
                # Add error to progress tracking
                global scan_progress
                if self.scan_id in scan_progress:
                    scan_progress[self.scan_id]['errors'].append({
                        'time': datetime.utcnow().isoformat(),
                        'message': str(e),
                        'trace': error_trace
                    })
                
                # Mark scan as failed
                scan = Scan.query.get(self.scan_id)
                if scan:
                    scan.status = 'Failed'
                    self.db.session.commit()
                print(f"❌ Scanner Error: {e}")
                return {'success': False, 'message': str(e)}
            finally:
                self._cleanup()
    
    def _validate_config(self):
        """Validate scan configuration before starting."""
        if not self.base_url:
            return {'valid': False, 'message': 'Base URL is required'}
        
        try:
            parsed = urlparse(self.base_url)
            if not parsed.scheme or not parsed.netloc:
                return {'valid': False, 'message': 'Invalid URL format'}
            if parsed.scheme not in ['http', 'https']:
                return {'valid': False, 'message': 'URL must use http or https'}
        except Exception:
            return {'valid': False, 'message': 'Invalid URL format'}
        
        # Validate limits
        if self.max_depth < 1 or self.max_depth > 10:
            self.max_depth = 3
        if self.max_pages < 1 or self.max_pages > 500:
            self.max_pages = 100
        if self.crawl_delay_ms < 0:
            self.crawl_delay_ms = 200
        if self.timeout_seconds < 5 or self.timeout_seconds > 120:
            self.timeout_seconds = 30
            self.timeout_ms = max(5000, self.timeout_seconds * 1000)
        
        return {'valid': True, 'message': 'Configuration valid'}
    
    def _init_playwright(self):
        """Initialize Playwright browser."""
        from playwright.sync_api import sync_playwright
        
        print("🎭 Initializing Playwright browser...")
        self.playwright = sync_playwright().start()
        
        # Launch visible browser if manual login is enabled
        if self.manual_login:
            print("👁️ Manual login enabled - launching VISIBLE browser")
            self.browser = self.playwright.chromium.launch(
                headless=False,
                slow_mo=100  # Slight delay to make actions visible
            )
        else:
            self.browser = self.playwright.chromium.launch(headless=True)
        
        print("✅ Playwright browser initialized")
    
    def _create_role_context(self, role):
        """
        Create a browser context for a specific role.
        
        For Guest: Fresh context with no authentication
        For Admin/User: New context with authentication
        
        Returns:
            Browser context or None if auth fails
        """
        context = self.browser.new_context()
        
        if role == 'guest':
            # Guest = fresh context, no login, no cookies
            print("👤 Created Guest context (unauthenticated)")
            return context
        
        # Find credentials for this role
        creds = None
        for profile in self.auth_profiles:
            if profile.get('role_name', '').lower() == role:
                creds = profile
                break
        
        if not creds or not creds.get('username') or not creds.get('password'):
            print(f"⚠️ No credentials found for {role}")
            context.close()
            return None
        
        # Perform authentication
        success = self._perform_login(context, creds, role)

        if success:
            self._maybe_apply_dvwa_security_level(context, role)
            print(f"✅ {role.capitalize()} authenticated successfully")
            return context
        else:
            # Automatic login failed - try manual login if enabled
            if self.manual_login:
                login_url = creds.get('login_url', f"{self.base_url}/login")
                print(f"⚠️ Auto-login failed for {role}, attempting manual login...")
                manual_success = self._perform_manual_login(context, login_url, role)
                if manual_success:
                    self._maybe_apply_dvwa_security_level(context, role)
                    print(f"✅ {role.capitalize()} manual authentication successful")
                    return context
            
            print(f"❌ {role.capitalize()} authentication failed")
            context.close()
            return None

    
    def _maybe_apply_dvwa_security_level(self, context, role_name):
        """
        Best-effort: if configured, attempt to set DVWA's security level for this
        authenticated browser context by visiting `security.php` and submitting the form.
        """
        if not self.dvwa_security_level:
            return

        security_url = urljoin(self.base_url.rstrip('/') + '/', 'security.php')
        page = None

        try:
            page = context.new_page()
            page.goto(security_url, timeout=self.timeout_ms, wait_until='domcontentloaded')

            select_locator = page.locator('select[name="security"]')
            if select_locator.count() == 0:
                return

            select_locator.select_option(self.dvwa_security_level)

            if page.locator('input[name="seclev_submit"]').count() > 0:
                page.click('input[name="seclev_submit"]')
            elif page.locator('button[type="submit"]').count() > 0:
                page.click('button[type="submit"]')

            try:
                page.wait_for_load_state('domcontentloaded', timeout=self.timeout_ms)
            except Exception:
                pass

            verify_ok = False
            selected = None
            try:
                selected = select_locator.input_value()
                if selected and selected.lower() == self.dvwa_security_level:
                    verify_ok = True
            except Exception:
                selected = None

            try:
                cookies = context.cookies()
                for cookie in cookies:
                    if cookie.get('name', '').lower() == 'security':
                        if (cookie.get('value') or '').lower() == self.dvwa_security_level:
                            verify_ok = True
                        break
            except Exception:
                pass

            if not verify_ok:
                warning = (
                    f"[{role_name}] DVWA security verification failed. "
                    f"Requested '{self.dvwa_security_level}', select='{selected}'."
                )
                print(f"WARNING: {warning}")
                global scan_progress
                if self.scan_id in scan_progress:
                    scan_progress[self.scan_id]['errors'].append({
                        'time': datetime.utcnow().isoformat(),
                        'message': warning
                    })
            else:
                print(f"[{role_name}] DVWA security level set to: {self.dvwa_security_level}")
        except Exception as e:
            print(f"WARNING: [{role_name}] DVWA security level apply failed: {e}")
        finally:
            try:
                if page:
                    page.close()
            except Exception:
                pass

    def _perform_login(self, context, profile, role_name):
        """
        Perform login using Playwright form automation.

        Returns:
            bool: True if login successful
        """
        try:
            page = context.new_page()
            login_url = profile.get('login_url', f"{self.base_url}/login")
            username = profile.get('username')
            password = profile.get('password')

            print(f"Login attempt for {role_name} at: {login_url}")
            page.goto(login_url, timeout=self.timeout_ms, wait_until='domcontentloaded')

            username_selector = profile.get('username_selector') or profile.get('email_selector')
            password_selector = profile.get('password_selector')
            submit_selector = profile.get('submit_selector')
            post_login_selector = profile.get('post_login_selector')
            success_url_contains = profile.get('login_success_url_contains')

            username_selectors = [
                username_selector,
                'input[name="username"]',
                'input[name="email"]',
                'input[type="email"]',
                'input[id="username"]',
                'input[id="email"]',
                'input[placeholder*="email" i]',
                'input[placeholder*="username" i]',
            ]
            username_selectors = [s for s in username_selectors if s]

            password_selectors = [
                password_selector,
                'input[name="password"]',
                'input[type="password"]',
                'input[id="password"]',
                'input[placeholder*="password" i]',
            ]
            password_selectors = [s for s in password_selectors if s]

            submit_selectors = [
                submit_selector,
                'button[type="submit"]',
                'input[type="submit"]',
                'button:has-text("Login")',
                'button:has-text("Sign in")',
                'button:has-text("Log in")',
            ]
            submit_selectors = [s for s in submit_selectors if s]

            # Fill username/email
            username_filled = False
            for selector in username_selectors:
                try:
                    if page.locator(selector).count() > 0:
                        page.fill(selector, username)
                        username_filled = True
                        break
                except Exception:
                    continue

            if not username_filled:
                page.close()
                return False

            # Fill password
            password_filled = False
            for selector in password_selectors:
                try:
                    if page.locator(selector).count() > 0:
                        page.fill(selector, password)
                        password_filled = True
                        break
                except Exception:
                    continue

            if not password_filled:
                page.close()
                return False

            # Submit form
            for selector in submit_selectors:
                try:
                    if page.locator(selector).count() > 0:
                        page.click(selector)
                        break
                except Exception:
                    continue

            # Wait for navigation or post-login selector
            try:
                page.wait_for_load_state('domcontentloaded', timeout=self.timeout_ms)
            except Exception:
                pass

            # Success heuristics
            current_url = page.url.lower()
            if success_url_contains and success_url_contains.lower() in current_url:
                page.close()
                return True

            if post_login_selector:
                try:
                    if page.locator(post_login_selector).count() > 0:
                        page.close()
                        return True
                except Exception:
                    pass

            content = ''
            try:
                content = page.content().lower()
            except Exception:
                content = ''

            login_form_present = self._detect_login_form(page)
            auth_indicators = self._detect_auth_indicators(content)
            # For SPA sites, also check hash-based routes
            login_keywords = ['login', 'signin', 'sign-in', 'auth', '#/login', '#/signin']
            still_on_login = any(k in current_url for k in login_keywords)
            
            # For SPA sites, wait a bit longer for navigation to complete
            if self.spa_mode and still_on_login:
                try:
                    page.wait_for_timeout(2000)
                    current_url = page.url.lower()
                    still_on_login = any(k in current_url for k in login_keywords)
                    content = page.content().lower()
                    login_form_present = self._detect_login_form(page)
                    auth_indicators = self._detect_auth_indicators(content)
                except Exception:
                    pass

            page.close()

            if auth_indicators and not login_form_present:
                return True
            if not still_on_login and not login_form_present:
                return True

            return False

        except Exception as e:
            print(f"Login error for {role_name}: {e}")
            return False

    def _perform_manual_login(self, context, login_url, role_name):
        """
        Open a visible browser window for manual login.
        User has LOGIN_WAIT_SECONDS to complete the login.
        
        Returns:
            bool: True if login detected as successful
        """
        page = None
        try:
            page = context.new_page()
            print(f"\n" + "="*60)
            print(f"🔐 MANUAL LOGIN REQUIRED for {role_name.upper()}")
            print(f"="*60)
            print(f"Browser window opened at: {login_url}")
            print(f"You have {self.login_wait_seconds} seconds to complete login.")
            print(f"The scan will continue automatically after login is detected.")
            print(f"="*60 + "\n")
            
            page.goto(login_url, timeout=30000, wait_until='domcontentloaded')
            if self.spa_mode:
                try:
                    page.wait_for_load_state('networkidle', timeout=8000)
                except Exception:
                    pass
                try:
                    page.wait_for_timeout(750)
                except Exception:
                    pass
            
            # Store initial URL for comparison
            initial_url = page.url.lower()
            
            # Wait for user to complete login
            # Check every 2 seconds if we've left the login page
            wait_interval = 2
            total_waited = 0
            
            while total_waited < self.login_wait_seconds:
                time.sleep(wait_interval)
                total_waited += wait_interval
                
                # Check if page is still open (user might close browser)
                try:
                    current_url = page.url.lower()
                except Exception:
                    # Page was closed - treat as success if we're not on login anymore
                    print(f"\n⚠️ Browser page closed by user")
                    return False

                try:
                    content = page.content().lower()
                except Exception:
                    content = ''

                login_form_present = self._detect_login_form(page)
                auth_indicators = self._detect_auth_indicators(content)

                # For SPA sites, check hash fragments too
                login_patterns = ['login', 'signin', 'sign-in', 'auth', '#/login', '#/signin']
                on_login_page = any(p in current_url for p in login_patterns)
                
                if auth_indicators and not login_form_present:
                    print(f"\n✅ Login detected! Continuing scan...")
                    try:
                        page.close()
                    except Exception:
                        pass
                    return True

                # Check if we've navigated away from login page
                if not on_login_page:
                    if auth_indicators or not login_form_present:
                        print(f"\n✅ Login detected! Continuing scan...")
                        try:
                            page.close()
                        except Exception:
                            pass
                        return True

                # Also check if URL has changed significantly (for SPAs with hash routing)
                if current_url != initial_url and not on_login_page:
                    print(f"\n✅ Login detected (URL changed)! Continuing scan...")
                    try:
                        page.close()
                    except Exception:
                        pass
                    return True

                # Show progress every 10 seconds
                if total_waited % 10 == 0:
                    remaining = self.login_wait_seconds - total_waited
                    print(f"⏳ Waiting for login... {remaining}s remaining")
            
            # Timeout reached
            print(f"\n⚠️ Manual login timeout reached ({self.login_wait_seconds}s)")
            
            # Final check
            try:
                current_url = page.url.lower()
            except Exception:
                return False
                
            login_patterns = ['login', 'signin', 'sign-in', 'auth', '#/login', '#/signin']
            on_login_page = any(p in current_url for p in login_patterns)
            
            if not on_login_page:
                print(f"✅ Login appears successful (navigated away from login page)")
                try:
                    page.close()
                except Exception:
                    pass
                return True

            try:
                content = page.content().lower()
            except Exception:
                content = ''
            if self._detect_auth_indicators(content) and not self._detect_login_form(page):
                print(f"✅ Login appears successful (auth indicators detected)")
                try:
                    page.close()
                except Exception:
                    pass
                return True
            
            try:
                page.close()
            except Exception:
                pass
            return False
            
        except Exception as e:
            print(f"⚠️ Manual login error for {role_name}: {e}")
            if page:
                try:
                    page.close()
                except Exception:
                    pass
            return False
    
    def _should_skip_url(self, url):
        """
        Check if a URL should be skipped to avoid session invalidation or mutations.
        Returns True if URL should NOT be crawled.
        """
        if not url:
            return True
        url_lower = url.lower()

        denylist = [
            'logout', 'logoff', 'signout', 'sign-out', 'signoff', 'log-out',
            'delete', 'remove', 'destroy', 'drop', 'update', 'transfer',
            'checkout', 'purchase', 'buy', 'order', 'pay', 'payment',
            'admin/delete', 'admin/remove', 'admin/update', 'admin/transfer',
            'reset', 'reboot', 'setup', 'install', 'init'
        ]

        return any(pattern in url_lower for pattern in denylist)

    def _normalize_url(self, url):
        """Normalize URL: canonicalize query order, trim trailing slash, and optionally preserve SPA fragments."""
        if not url:
            return None
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                return None

            scheme = parsed.scheme.lower()
            netloc = parsed.netloc.lower()

            if scheme == 'http' and netloc.endswith(':80'):
                netloc = netloc[:-3]
            if scheme == 'https' and netloc.endswith(':443'):
                netloc = netloc[:-4]

            path = parsed.path or '/'
            if len(path) > 1:
                path = path.rstrip('/')

            query = ''
            if parsed.query:
                query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))

            fragment = ''
            if self.spa_mode and parsed.fragment and parsed.fragment.startswith('/'):
                frag = parsed.fragment
                if '?' in frag:
                    frag_path, frag_query = frag.split('?', 1)
                else:
                    frag_path, frag_query = frag, ''

                if len(frag_path) > 1:
                    frag_path = frag_path.rstrip('/')

                fragment = frag_path
                if frag_query:
                    fragment = f"{frag_path}?{frag_query}"

            return urlunparse((scheme, netloc, path, '', query, fragment))
        except Exception:
            return None

    def _is_static_asset(self, url):
        if not url:
            return True
        url_lower = url.lower()
        skip_extensions = [
            '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
            '.woff', '.woff2', '.ttf', '.eot', '.pdf', '.zip', '.rar', '.7z'
        ]
        return any(url_lower.endswith(ext) for ext in skip_extensions)

    def _is_html_response(self, response):
        if not response:
            return False
        try:
            content_type = response.headers.get('content-type', '').lower()
            if not content_type:
                return True
            return 'text/html' in content_type or 'application/xhtml+xml' in content_type
        except Exception:
            return True

    def _detect_login_form(self, page):
        try:
            if page.locator('input[type="password"]').count() > 0:
                return True
            if page.locator('form:has(input[type="password"])').count() > 0:
                return True
        except Exception:
            return False
        return False

    def _extract_fingerprint(self, page):
        """Extract a stable content fingerprint from visible text."""
        normalized_text = ''
        try:
            raw_text = page.evaluate("() => document.body ? (document.body.innerText || '') : ''")
            normalized_text = re.sub(r'\s+', ' ', raw_text or '').strip()
        except Exception:
            normalized_text = ''

        if len(normalized_text) > 200000:
            normalized_text = normalized_text[:200000]

        text_hash = hashlib.sha256(
            normalized_text.encode('utf-8', errors='ignore')
        ).hexdigest() if normalized_text else ''

        return {
            'text': normalized_text,
            'text_hash': text_hash,
            'text_len': len(normalized_text),
            'excerpt': normalized_text[:200]
        }

    def _detect_denial_signals(self, page, final_url, status, normalized_text, redirect_chain):
        denial_keywords = [
            'access denied', 'forbidden', 'unauthorized', 'permission',
            'not allowed', 'authentication required', 'login required'
        ]

        login_patterns = ['login', 'signin', 'sign-in']
        final_url_lower = (final_url or '').lower()
        redirect_chain_lower = [(u or '').lower() for u in (redirect_chain or [])]

        redirect_to_login = any(p in final_url_lower for p in login_patterns)
        if not redirect_to_login:
            redirect_to_login = any(any(p in u for p in login_patterns) for u in redirect_chain_lower)

        # Also check known login URL paths
        for profile in self.auth_profiles:
            login_url = profile.get('login_url')
            if not login_url:
                continue
            try:
                login_path = urlparse(login_url).path.lower()
                if login_path and login_path in final_url_lower:
                    redirect_to_login = True
                    break
            except Exception:
                continue

        login_form = self._detect_login_form(page)
        text_lower = (normalized_text or '').lower()
        denial_hits = [kw for kw in denial_keywords if kw in text_lower]

        return {
            'status_denied': status in (401, 403),
            'redirect_to_login': redirect_to_login,
            'login_form': login_form,
            'denial_keywords': len(denial_hits) > 0,
            'denial_keyword_matches': denial_hits
        }

    def _classify_access(self, status, denial_signals):
        denied_like = False
        if status in (401, 403):
            denied_like = True
        if denial_signals.get('redirect_to_login'):
            denied_like = True
        if denial_signals.get('login_form'):
            denied_like = True
        if denial_signals.get('denial_keywords'):
            denied_like = True

        allowed_like = False
        if status and 200 <= status < 300 and not denied_like:
            allowed_like = True

        return allowed_like, denied_like

    def _has_strong_auth_indicators(self, data):
        text = (data or {}).get('text_sample') or (data or {}).get('text_excerpt') or ''
        if not text:
            return False
        text_lower = text.lower()
        strong_indicators = [
            'logout', 'log out', 'sign out', 'signout',
            'dashboard', 'admin panel'
        ]
        return any(indicator in text_lower for indicator in strong_indicators)

    def _spa_route_classification(self, url):
        if not self.spa_mode or not url:
            return None

        try:
            parsed = urlparse(url)
            path = (parsed.path or '').lower()
            fragment = (parsed.fragment or '').lower()
        except Exception:
            path = ''
            fragment = ''

        target = f"{path} {fragment}"

        admin_keywords = [
            'admin', 'administration', 'manage', 'users', 'roles'
        ]
        auth_keywords = [
            'profile', 'account', 'orders', 'order', 'basket',
            'wallet', 'address', 'payment', 'complaint', 'history'
        ]

        if any(keyword in target for keyword in admin_keywords):
            return 'admin'
        if any(keyword in target for keyword in auth_keywords):
            return 'auth'

        return None

    def _is_protected_url(self, url, admin_data, user_data, guest_data):
        admin_allowed = (admin_data or {}).get('allowed_like', False)
        if not admin_allowed:
            return False

        user_denied = (user_data or {}).get('denied_like', False)
        guest_denied = (guest_data or {}).get('denied_like', False)
        if user_denied or guest_denied:
            return True

        if self.spa_mode and self._spa_route_classification(url):
            return True

        if self._has_strong_auth_indicators(admin_data):
            denial_keywords = (admin_data or {}).get('denial_signals', {}).get('denial_keywords')
            if not denial_keywords:
                return True

        return False

    def _is_auth_gated_by_observation(self, admin_data, user_data, guest_data):
        admin_allowed = (admin_data or {}).get('allowed_like', False)
        if not admin_allowed:
            return False
        user_denied = (user_data or {}).get('denied_like', False)
        guest_denied = (guest_data or {}).get('denied_like', False)
        return user_denied or guest_denied

    def _get_redirect_chain(self, response):
        if not response:
            return []
        chain = []
        try:
            req = response.request
            while req and req.redirected_from:
                req = req.redirected_from
                if req:
                    chain.append(req.url)
            chain.reverse()
        except Exception:
            return []
        return chain

    def _record_url_data(self, url, role, data):
        if url not in self.url_data:
            self.url_data[url] = {}
        self.url_data[url][role] = data

    def _visit_url(self, context, url):
        page = context.new_page()
        try:
            response = page.goto(url, timeout=self.timeout_ms, wait_until='domcontentloaded')
            if self.spa_mode:
                try:
                    page.wait_for_load_state('networkidle', timeout=min(8000, self.timeout_ms))
                except Exception:
                    pass
                try:
                    page.wait_for_timeout(750)
                except Exception:
                    pass
            status = response.status if response else 0
            final_url = page.url
            redirect_chain = self._get_redirect_chain(response)
            try:
                title = page.title()
            except Exception:
                title = ''

            fingerprint = self._extract_fingerprint(page)
            denial_signals = self._detect_denial_signals(
                page,
                final_url,
                status,
                fingerprint['text'],
                redirect_chain
            )
            auth_indicators = self._detect_auth_indicators(fingerprint['text'])
            allowed_like, denied_like = self._classify_access(status, denial_signals)

            return {
                'status': status,
                'final_url': final_url,
                'redirect_chain': redirect_chain,
                'title': title,
                'text_hash': fingerprint['text_hash'],
                'text_len': fingerprint['text_len'],
                'text_excerpt': fingerprint['excerpt'],
                'text_sample': fingerprint['text'][:2000],
                'denial_signals': denial_signals,
                'has_login_form': denial_signals.get('login_form', False),
                'has_auth_indicators': auth_indicators,
                'allowed_like': allowed_like,
                'denied_like': denied_like
            }
        finally:
            try:
                page.close()
            except Exception:
                pass

    def _crawl_as_role(self, role, start_url, depth=0):
        """
        Crawl URLs as a specific role.
        Each role maintains its own visited URLs set.
        """
        context = self.role_contexts.get(role)
        if not context:
            return

        start_url = self._normalize_url(start_url) or start_url
        queue = deque([(start_url, 0)])
        visited = self.urls_by_role.get(role, set())

        if self.spa_mode:
            base = self.base_url or start_url
            for seed in self._get_spa_seed_routes():
                seeded = self._normalize_url(f"{base}{seed}")
                if seeded and self._is_in_scope(seeded):
                    queue.append((seeded, 1))

        while queue and len(visited) < self.max_pages:
            url, current_depth = queue.popleft()
            if current_depth > self.max_depth:
                continue

            url = self._normalize_url(url) or url
            if not url or url in visited:
                continue
            if not self._is_in_scope(url):
                continue
            if self._should_skip_url(url):
                print(f"[{role}] Skipping dangerous URL: {url}")
                continue
            if self._is_static_asset(url):
                continue

            time.sleep(self.crawl_delay_ms / 1000.0)

            page = context.new_page()
            try:
                response = page.goto(url, timeout=self.timeout_ms, wait_until='domcontentloaded')
                if self.spa_mode:
                    try:
                        page.wait_for_load_state('networkidle', timeout=min(8000, self.timeout_ms))
                    except Exception:
                        pass
                    try:
                        page.wait_for_timeout(750)
                    except Exception:
                        pass
                status = response.status if response else 0
                final_url = page.url
                redirect_chain = self._get_redirect_chain(response)
                try:
                    title = page.title()
                except Exception:
                    title = ''

                fingerprint = self._extract_fingerprint(page)
                denial_signals = self._detect_denial_signals(
                    page,
                    final_url,
                    status,
                    fingerprint['text'],
                    redirect_chain
                )
                auth_indicators = self._detect_auth_indicators(fingerprint['text'])
                allowed_like, denied_like = self._classify_access(status, denial_signals)

                data = {
                    'status': status,
                    'final_url': final_url,
                    'redirect_chain': redirect_chain,
                    'title': title,
                    'text_hash': fingerprint['text_hash'],
                    'text_len': fingerprint['text_len'],
                    'text_excerpt': fingerprint['excerpt'],
                    'text_sample': fingerprint['text'][:2000],
                    'denial_signals': denial_signals,
                    'has_login_form': denial_signals.get('login_form', False),
                    'has_auth_indicators': auth_indicators,
                    'allowed_like': allowed_like,
                    'denied_like': denied_like
                }

                self._record_url_data(url, role, data)
                visited.add(url)
                self.all_discovered_urls.add(url)

                access_flag = 'OK' if allowed_like else 'DENIED'
                print(f"[{role}] {access_flag} ({current_depth}): {url}")

                self._update_progress(
                    current_url=url,
                    urls_discovered=len(self.all_discovered_urls)
                )

                if response and self._is_html_response(response) and allowed_like:
                    links = self._extract_links(page, final_url)
                    for link in links:
                        if len(visited) >= self.max_pages:
                            break
                        if link not in visited and self._is_in_scope(link):
                            queue.append((link, current_depth + 1))

            except Exception as e:
                print(f"[{role}] Crawl error for {url}: {e}")
            finally:
                try:
                    page.close()
                except Exception:
                    pass

    def _detect_auth_indicators(self, content):
        """
        Detect if page content shows indicators of an authenticated session.
        Returns True if the page appears to show logged-in content.
        """
        content_lower = (content or '').lower()

        auth_indicators = [
            'logout', 'log out', 'sign out', 'signout',
            'my account', 'my profile', 'profile',
            'welcome,', 'dashboard', 'admin panel',
            'user settings', 'account settings',
            'logged in as', 'you are logged in',
            # DVWA specific
            'dvwa security', 'security level', 'phpids',
            # Juice Shop hints
            'your basket', 'order history'
        ]

        return any(indicator in content_lower for indicator in auth_indicators)

    def _extract_links(self, page, current_url):
        """Extract in-scope links from anchors, forms, and iframes without clicking."""
        links = set()

        try:
            selectors = [
                ('a[href]', 'href'),
                ('form[action]', 'action'),
                ('iframe[src]', 'src')
            ]

            for selector, attr in selectors:
                elements = page.query_selector_all(selector)
                for elem in elements:
                    try:
                        raw = elem.get_attribute(attr)
                        if not raw:
                            continue
                        absolute_url = self._resolve_url(current_url, raw)
                        if not absolute_url:
                            continue
                        if self._is_in_scope(absolute_url):
                            links.add(absolute_url)
                    except Exception:
                        continue

            onclick_elements = page.query_selector_all('[onclick]')
            for elem in onclick_elements:
                try:
                    onclick = elem.get_attribute('onclick')
                    if not onclick:
                        continue
                    url_matches = re.findall(
                        r'(?:location\.href|window\.location)\s*=\s*[\'"]([^\'"]+)[\'"]',
                        onclick
                    )
                    for match in url_matches:
                        absolute_url = self._resolve_url(current_url, match)
                        if absolute_url and self._is_in_scope(absolute_url):
                            links.add(absolute_url)
                except Exception:
                    continue

            if links:
                print(f"    Found {len(links)} links on {current_url.split('/')[-1] or 'index'}")

        except Exception as e:
            print(f"Link extraction error: {e}")

        if self.spa_mode:
            try:
                spa_candidates = page.evaluate("""() => {
                    const routes = new Set();
                    const add = (val) => {
                        if (!val || typeof val !== 'string') return;
                        routes.add(val.trim());
                    };
                    document.querySelectorAll('a[href]').forEach(a => add(a.getAttribute('href')));
                    document.querySelectorAll('[routerlink]').forEach(el => add(el.getAttribute('routerlink')));
                    document.querySelectorAll('[ng-reflect-router-link]').forEach(el => add(el.getAttribute('ng-reflect-router-link')));
                    return Array.from(routes);
                }""")

                base = self.base_url or current_url
                for raw in spa_candidates or []:
                    if not raw or raw.startswith('javascript:') or raw.startswith('mailto:') or raw.startswith('tel:'):
                        continue

                    resolved = None
                    if raw.startswith('#/'):
                        resolved = self._normalize_url(f"{base}{raw}")
                    elif raw.startswith('/#/'):
                        resolved = self._normalize_url(urljoin(base, raw))
                    elif raw.startswith('/'):
                        resolved = self._normalize_url(f"{base}/#/{raw.lstrip('/')}")
                    else:
                        resolved = self._resolve_url(base, raw)

                    if resolved and self._is_in_scope(resolved):
                        links.add(resolved)
            except Exception as e:
                print(f"SPA link extraction error: {e}")

            try:
                base = self.base_url or current_url
                for seed in self._get_spa_seed_routes():
                    resolved = self._normalize_url(f"{base}{seed}")
                    if resolved and self._is_in_scope(resolved):
                        links.add(resolved)
            except Exception:
                pass

        return links

    def _cross_role_test(self):
        """
        Test ALL discovered URLs with EACH role.
        """
        print("Cross-Role Testing Phase")
        print(f"   Testing {len(self.all_discovered_urls)} URLs across {len(self.roles_to_crawl)} roles")

        urls_to_test = list(self.all_discovered_urls)
        total_tests = 0
        total_urls = len(urls_to_test)

        for role in self.roles_to_crawl:
            context = self.role_contexts.get(role)
            if not context:
                continue

            print(f"   [{role}] Testing {total_urls} URLs...")
            for idx, url in enumerate(urls_to_test):
                if self._should_skip_url(url) or self._is_static_asset(url):
                    continue

                time.sleep(self.crawl_delay_ms / 1000.0)

                try:
                    data = self._visit_url(context, url)
                    self._record_url_data(url, role, data)

                    access_flag = 'OK' if data.get('allowed_like') else 'DENIED'
                    print(f"      [{role}] {access_flag}: {url.split('/')[-1] or url}")
                    total_tests += 1

                    self._update_progress(
                        current_url=url,
                        urls_tested=total_tests,
                        progress_percent=70 + int((idx / max(1, total_urls)) * 8)
                    )

                except Exception as e:
                    print(f"      [{role}] Error testing {url}: {e}")

        print(f"   Cross-role testing complete: {total_tests} tests")
        if self.spa_mode:
            spa_routes = set()
            for url in self.all_discovered_urls:
                try:
                    frag = urlparse(url).fragment or ''
                except Exception:
                    frag = ''
                if frag.startswith('/'):
                    spa_routes.add(frag)
            print(f"SPA routes discovered: {len(spa_routes)}")
        if self.debug_access_matrix:
            print("Access Matrix (debug_access_matrix):")
            for url in sorted(self.all_discovered_urls):
                info = self.url_data.get(url, {})
                admin_data = info.get('admin', {})
                user_data = info.get('user', {})
                guest_data = info.get('guest', {})
                protected = self._is_protected_url(url, admin_data, user_data, guest_data)
                def access_label(data):
                    if (data or {}).get('allowed_like'):
                        return 'allowed'
                    if (data or {}).get('denied_like'):
                        return 'denied'
                    return 'unknown'
                print(
                    f"{url} | admin={access_label(admin_data)} | "
                    f"user={access_label(user_data)} | guest={access_label(guest_data)} | "
                    f"protected={protected}"
                )

    def _resolve_url(self, base_url, href):
        """Resolve relative URL to absolute and normalize."""
        try:
            if not href:
                return None
            if href.startswith('javascript:') or href.startswith('mailto:') or href.startswith('tel:'):
                return None
            absolute = urljoin(base_url, href)
            return self._normalize_url(absolute)
        except Exception:
            return None

    def _is_in_scope(self, url):
        """
        Check if URL is within the scan scope.
        Must be same domain AND under the base path.
        """
        try:
            if not url:
                return False
            base_parsed = urlparse(self.base_url)
            url_parsed = urlparse(url)

            base_domain = base_parsed.netloc.lower()
            url_domain = url_parsed.netloc.lower()

            if base_domain != url_domain:
                return False

            url_path = (url_parsed.path or '/').lower().rstrip('/')
            if not url_path:
                url_path = '/'

            if self.base_path == '/':
                return True

            return url_path.startswith(self.base_path) or url_path == self.base_path
        except Exception:
            return False

    def _similar_content(self, data_a, data_b):
        if not data_a or not data_b:
            return False
        hash_a = data_a.get('text_hash')
        hash_b = data_b.get('text_hash')
        if hash_a and hash_b and hash_a == hash_b:
            return True
        sample_a = data_a.get('text_sample', '')
        sample_b = data_b.get('text_sample', '')
        if not sample_a or not sample_b:
            return False
        ratio = difflib.SequenceMatcher(None, sample_a, sample_b).ratio()
        return ratio >= 0.9

    def _confidence_for_violation(self, higher_role_data, lower_role_data):
        if not lower_role_data:
            return 'Low'
        high_status = (higher_role_data or {}).get('status')
        low_status = lower_role_data.get('status')
        high_denied = (higher_role_data or {}).get('denied_like')
        low_allowed = lower_role_data.get('allowed_like')
        high_redirect = (higher_role_data or {}).get('denial_signals', {}).get('redirect_to_login')

        if low_allowed and high_denied:
            return 'High'
        if low_allowed and high_redirect:
            return 'High'
        if high_status in (401, 403) and low_status and 200 <= low_status < 300:
            return 'High'

        if low_status and high_status and 200 <= low_status < 300 and 200 <= high_status < 300:
            denial_a = (higher_role_data or {}).get('denial_signals', {}).get('denial_keywords')
            denial_b = lower_role_data.get('denial_signals', {}).get('denial_keywords')
            if denial_a != denial_b and not self._similar_content(higher_role_data, lower_role_data):
                return 'Medium'

        return 'Low'

    def _classify_expected_access(self, url, role, discovered_admin, discovered_user, discovered_guest, is_protected):
        if role == 'guest':
            if discovered_guest:
                return 'Allowed' if not is_protected else 'Denied'
            if discovered_admin or discovered_user or is_protected:
                return 'Denied'
        if role == 'user':
            if is_protected and discovered_admin and not discovered_user and not discovered_guest:
                return 'Denied'
        return 'Allowed'

    def _compare_roles_to_find_violations(self):
        from app.models import URL

        url_rows = URL.query.filter_by(scan_id=self.scan_id).all()
        url_id_map = {u.url: u.url_id for u in url_rows}

        admin_discovered = self.urls_by_role.get('admin', set())
        user_discovered = self.urls_by_role.get('user', set())
        guest_discovered = self.urls_by_role.get('guest', set())

        recorded = set()

        for url in self.all_discovered_urls:
            url_id = url_id_map.get(url)
            if not url_id:
                continue

            url_info = self.url_data.get(url, {})
            admin_data = url_info.get('admin', {})
            user_data = url_info.get('user', {})
            guest_data = url_info.get('guest', {})

            admin_allowed = admin_data.get('allowed_like', False)
            user_allowed = user_data.get('allowed_like', False)
            guest_allowed = guest_data.get('allowed_like', False)
            guest_denied = guest_data.get('denied_like', False)

            in_admin = url in admin_discovered
            in_user = url in user_discovered
            in_guest = url in guest_discovered

            is_protected = self._is_protected_url(url, admin_data, user_data, guest_data)
            auth_required_observed = self._is_auth_gated_by_observation(admin_data, user_data, guest_data)
            spa_class = self._spa_route_classification(url)

            def record_violation(role, violation_type, higher_role_data, lower_role_data):
                key = (url_id, role, violation_type)
                if key in recorded:
                    return
                recorded.add(key)

                expected = self._classify_expected_access(
                    url,
                    role,
                    in_admin,
                    in_user,
                    in_guest,
                    is_protected
                )
                actual = 'Allowed' if lower_role_data.get('allowed_like') else 'Denied'

                confidence = self._confidence_for_violation(higher_role_data, lower_role_data)
                self._record_violation(
                    url_id=url_id,
                    role=role,
                    violation_type=violation_type,
                    expected=expected,
                    actual=actual,
                    evidence={
                        'url': url,
                        'status': lower_role_data.get('status'),
                        'final_url': lower_role_data.get('final_url'),
                        'denial_signals': lower_role_data.get('denial_signals'),
                        'text_hash': lower_role_data.get('text_hash'),
                        'confidence': confidence
                    }
                )

            # Detection 1: Guest sees authenticated content
            if self.test_bac and guest_allowed and admin_allowed and guest_data.get('has_auth_indicators'):
                if self._similar_content(admin_data, guest_data):
                    record_violation(
                        role='guest',
                        violation_type='Unauthorized Access - Guest sees authenticated content',
                        higher_role_data=admin_data,
                        lower_role_data=guest_data
                    )

            # Detection 2: Guest sees same content as admin on protected paths
            if self.test_bac and guest_allowed and admin_allowed and is_protected:
                if self._similar_content(admin_data, guest_data):
                    record_violation(
                        role='guest',
                        violation_type='Unauthorized Access - Guest matches admin content',
                        higher_role_data=admin_data,
                        lower_role_data=guest_data
                    )
                elif self.spa_mode and spa_class in ('auth', 'admin'):
                    record_violation(
                        role='guest',
                        violation_type='Unauthorized Access - Guest access to protected SPA route',
                        higher_role_data=admin_data,
                        lower_role_data=guest_data
                    )

            # Detection 3: Forced browsing (guest accesses URL not discovered as guest)
            if self.test_forced_browsing and is_protected and guest_allowed and not in_guest and (in_admin or in_user):
                record_violation(
                    role='guest',
                    violation_type='Forced Browsing - Guest accessed undiscovered URL',
                    higher_role_data=admin_data or user_data,
                    lower_role_data=guest_data
                )

            # Detection 4: User sees admin-only content
            if self.test_priv_esc and user_allowed and admin_allowed and is_protected:
                if guest_denied and self._similar_content(admin_data, user_data):
                    record_violation(
                        role='user',
                        violation_type='Privilege Escalation - User accessed admin-only content',
                        higher_role_data=admin_data,
                        lower_role_data=user_data
                    )
                elif self.spa_mode and spa_class == 'admin':
                    record_violation(
                        role='user',
                        violation_type='Privilege Escalation - User access to admin SPA route',
                        higher_role_data=admin_data,
                        lower_role_data=user_data
                    )

            # Detection 5: Auth-required pages accessible by guest
            if self.test_forced_browsing and guest_allowed and admin_allowed and auth_required_observed:
                record_violation(
                    role='guest',
                    violation_type='Unauthorized Access - Auth-required page accessible by guest',
                    higher_role_data=admin_data or user_data,
                    lower_role_data=guest_data
                )

            # Detection 6: Auth bypass on auth-gated URLs
            if self.test_auth_bypass and admin_allowed and auth_required_observed:
                if guest_allowed:
                    record_violation(
                        role='guest',
                        violation_type='Auth Bypass - Guest access on auth-gated URL',
                        higher_role_data=admin_data,
                        lower_role_data=guest_data
                    )
                if self.test_priv_esc and user_allowed and guest_denied and is_protected:
                    record_violation(
                        role='user',
                        violation_type='Auth Bypass - User access on auth-gated URL',
                        higher_role_data=admin_data,
                        lower_role_data=user_data
                    )

    def _compare_and_detect_violations(self):
        """Compare discovered URLs across roles to detect BAC violations."""
        print("Access Analysis:")
        print(f"   Admin discovered: {len(self.urls_by_role.get('admin', set()))} URLs")
        print(f"   User discovered: {len(self.urls_by_role.get('user', set()))} URLs")
        print(f"   Guest discovered: {len(self.urls_by_role.get('guest', set()))} URLs")
        print(f"   URL data tracked: {len(self.url_data)} URLs")

        self._compare_roles_to_find_violations()
        self.db.session.commit()

    def _persist_urls(self):
        """Persist discovered URLs and per-role status to the database."""
        from app.models import URL

        def status_str(value):
            return str(value) if value else None

        for url in sorted(self.all_discovered_urls):
            url_info = self.url_data.get(url, {})
            admin_status = status_str(url_info.get('admin', {}).get('status'))
            user_status = status_str(url_info.get('user', {}).get('status'))
            guest_status = status_str(url_info.get('guest', {}).get('status'))

            accessible_roles = []
            for role in self.roles_to_crawl:
                role_data = url_info.get(role, {})
                if role_data.get('allowed_like'):
                    accessible_roles.append(role)

            http_status = admin_status or user_status or guest_status
            url_record = URL.query.filter_by(scan_id=self.scan_id, url=url).first()

            if not url_record:
                url_record = URL(
                    scan_id=self.scan_id,
                    url=url,
                    http_status=http_status,
                    admin_status=admin_status,
                    user_status=user_status,
                    guest_status=guest_status,
                    accessible_roles=','.join(accessible_roles)
                )
                self.db.session.add(url_record)
            else:
                url_record.http_status = http_status
                url_record.admin_status = admin_status
                url_record.user_status = user_status
                url_record.guest_status = guest_status
                url_record.accessible_roles = ','.join(accessible_roles)

        self.db.session.commit()

    def _get_url_id(self, url):
        """Get URL record ID from database."""
        from app.models import URL
        url_record = URL.query.filter_by(scan_id=self.scan_id, url=url).first()
        return url_record.url_id if url_record else None
    
    def _record_violation(self, url_id, role, violation_type, expected, actual, evidence=None):
        """Record a violation to the database and store evidence in memory."""
        from app.models import Violation

        violation = Violation(
            url_id=url_id,
            role_attempted=role,
            expected_access=expected,
            actual_access=actual,
            violation_type=violation_type,
            created_at=datetime.utcnow()
        )
        self.db.session.add(violation)
        self.violations.append(violation)

        if evidence:
            self.violation_evidence.append(evidence)

    def _test_session_management(self):
        """Test session cookie security flags."""
        from app.models import Violation
        
        try:
            # Use first authenticated context
            context = None
            for role in ['admin', 'user']:
                if role in self.role_contexts:
                    context = self.role_contexts[role]
                    break
            
            if not context:
                return
            
            cookies = context.cookies()
            
            for cookie in cookies:
                issues = []
                name = cookie.get('name', '').lower()
                
                if 'session' in name or 'auth' in name or 'token' in name:
                    if not cookie.get('secure'):
                        issues.append('Missing Secure flag')
                    if not cookie.get('httpOnly'):
                        issues.append('Missing HttpOnly flag')
                    if cookie.get('sameSite', 'None') == 'None':
                        issues.append('SameSite=None')
                
                if issues:
                    # Get any URL to attach violation to
                    url_id = None
                    if self.all_discovered_urls:
                        url_id = self._get_url_id(list(self.all_discovered_urls)[0])
                    
                    if url_id:
                        self._record_violation(
                            url_id=url_id,
                            role='N/A',
                            violation_type='Session Management - ' + ', '.join(issues),
                            expected='secure_cookie',
                            actual=', '.join(issues)
                        )
                        print(f"🚨 Session issue: {issues}")
                    break
                    
        except Exception as e:
            print(f"⚠️ Session test error: {e}")
    
    def _generate_summary(self):
        """Generate scan summary."""
        summary = {
            'scan_id': self.scan_id,
            'base_url': self.base_url,
            'roles_crawled': list(self.urls_by_role.keys()),
            'urls_per_role': {role: len(urls) for role, urls in self.urls_by_role.items()},
            'total_urls': len(self.all_discovered_urls),
            'total_violations': len(self.violations),
            'auth_failures': self.auth_failures,
            'violation_types': {}
        }
        
        for v in self.violations:
            vtype = v.violation_type
            if vtype not in summary['violation_types']:
                summary['violation_types'][vtype] = 0
            summary['violation_types'][vtype] += 1
        
        return json.dumps(summary)
    
    def _cleanup(self):
        """Clean up Playwright resources."""
        try:
            for context in self.role_contexts.values():
                try:
                    context.close()
                except:
                    pass
            
            if self.browser:
                self.browser.close()
            if self.playwright:
                self.playwright.stop()
            print("🧹 Playwright resources cleaned up")
        except Exception as e:
            print(f"⚠️ Cleanup error: {e}")


def run_scan_background(scan_id, config, db, app):
    """
    Run a scan in a background thread.
    
    Args:
        scan_id: Database scan ID
        config: Scan configuration dict
        db: SQLAlchemy database instance  
        app: Flask app instance
    """
    def _run():
        scanner = QuickScanner(scan_id, config, db, app)
        result = scanner.run()
        print(f"✅ Scan {scan_id} completed: {result}")
    
    thread = Thread(target=_run, daemon=True)
    thread.start()
    return thread
