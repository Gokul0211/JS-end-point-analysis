#!/usr/bin/env python3
"""
Enhanced API Scanner v10.1 - Lab Reports & Obfuscated Code Fix
- Handles obfuscated/minified JavaScript patterns
- Improved base URL resolution (this.url, this.serverURL)
- Extended API indicators for lab/internal endpoints
- Better handling of property access patterns
- Reduced false positive filtering to catch all endpoints
- Exports to results.json and results.xlsx
"""
import requests
from bs4 import BeautifulSoup
import re
import json
import urllib.parse
import time
import sys
import os
from collections import defaultdict, deque

# Try importing Pandas for Excel export
try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

# ==============================================================================
# CONFIGURATION - OPTIMIZED FOR LAB REPORTS
# ==============================================================================
IGNORED_DOMAINS = [
    "google", "facebook", "twitter", "linkedin", "sentry", "datadog", "newrelic", 
    "segment", "hotjar", "optimizely", "intercom", "cloudflare", "cloudfront", 
    "jsdelivr", "cdnjs", "unpkg", "microsoftonline", "azure", "chinacloudapi", 
    "opencagedata", "tinymce", "w3.org", "gstatic", "bootstrapcdn", "fontawesome",
    "vimeo.com", "vzaar.com"
]

# MINIMAL noise filtering
NOISE_KEYWORDS = [
    'helvetica', 'arial', 'courier', 'times', 'verdana',
    '__html2canvas__', '_pseudoelement_',
    'klmnopqrstuvwxyz',
    'expressionchangedafterithasbeenchecked'
]

# MINIMAL blacklist
BASE_URL_BLACKLIST = [
    r'w3\.org', r'xmlns', r'2000/svg', r'1999/xhtml',
    r'ExpressionChangedAfterItHasBeenCheckedError',
    r'klmnopqrstuvwxyz',
]

STRICT_BLOCKS = [
    'webpack', '__webpack', 'sourcemap'
]

# MINIMAL false positives
FALSE_POSITIVE_PATTERNS = [
    r'^https?:$',
    r'w3\.org',
    r'xmlns',
    r'/1999/xhtml',
    r'/2000/svg',
    r'ExpressionChangedAfterItHasBeenCheckedError',
    r'klmnopqrstuvwxyz',
]

# EXPANDED - Include lab-related patterns
API_INDICATORS = [
    r'/api/', r'/v\d+/', r'/odata/', r'/rest/', r'/graphql', 
    r'\.json$', r'/endpoint', r'/service', r'/rpc',
    r'/lab', r'/report', r'/patient', r'/internal',
    r'/fetch', r'/get', r'/post', r'/update', r'/delete',
    r'/pdf', r'/export', r'/data', r'/his/', r'/zmedia/',
    r'/clinical', r'/notification', r'/forms/', r'/progress',
    r'/anesthesia', r'/ambulance', r'/vitals', r'/icu',
    r'/admin', r'/user', r'/auth', r'/zauth/'
]

LOW_VALUE_JS = [
    'polyfill', 'polyfills', 'core-js', 'zone.js', 
    'es2015', 'es5', 'babel', 'tslib', 'runtime'
]

# MINIMAL noise patterns
NOISE_PATTERNS = [
    r'^http:-',
    r'^http:/[^/]',
    r'^https?:px',
    r'^https?://[^/]*$',
]

# ==============================================================================
# CLASS: AGGRESSIVE VARIABLE RESOLVER WITH OBFUSCATION HANDLING
# ==============================================================================
class AggressiveVariableResolver:
    """Resolves ALL variable assignments including obfuscated/minified code"""
    
    def __init__(self):
        self.variables = {}
        self.file_variables = {}
        self.global_scope = {}
        self.potential_bases = {}
        self.property_accesses = {}
        self.obfuscated_strings = {}  # NEW: Track obfuscated string lookups
        
    def extract_all_variables(self, code, filename):
        """Extract ALL variable assignments - handles obfuscated code"""
        file_vars = {}
        
        # NEW: Extract obfuscated string array patterns
        # Pattern: const array = ['string1', 'string2', ...]
        self._extract_obfuscated_strings(code, filename)
        
        # Pattern 1: var/let/const declarations
        pattern1 = r'(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*["\']([^"\']{2,200})["\']'
        for match in re.finditer(pattern1, code):
            var_name = match.group(1)
            var_value = match.group(2)
            if not self._is_noise_value(var_value):
                self._register_variable(var_name, var_value, filename, file_vars, 90)
        
        # Pattern 2: this.url = ... or this.serverURL = ...
        pattern2 = r'this\.(url|serverURL|baseURL|apiURL)\s*=\s*["\']([^"\']{2,200})["\']'
        for match in re.finditer(pattern2, code):
            prop = match.group(1)
            var_value = match.group(2)
            if not self._is_noise_value(var_value):
                self._register_variable(f"this.{prop}", var_value, filename, file_vars, 98)
                self._register_variable(prop, var_value, filename, file_vars, 95)
                self.property_accesses[prop] = var_value
        
        # Pattern 3: this.url = someObj.serverURL or this.url = config.url
        # Fixed syntax error: wrapped regex in double quotes to handle single quotes inside
        pattern3 = r"this\.(url|serverURL|baseURL|apiURL)\s*=\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\[([\"'])([a-zA-Z_$][a-zA-Z0-9_$]*)\3\]"
        for match in re.finditer(pattern3, code):
            prop = match.group(1)
            source_obj = match.group(2)
            source_prop = match.group(4)
            # Track that this.prop comes from obj[prop]
            self.property_accesses[prop] = f"{source_obj}.{source_prop}"
        
        # Pattern 4: Object property assignments (this.prop = value)
        pattern4 = r'this\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*["\']([^"\']{2,200})["\']'
        for match in re.finditer(pattern4, code):
            prop = match.group(1)
            var_value = match.group(2)
            if not self._is_noise_value(var_value):
                self._register_variable(f"this.{prop}", var_value, filename, file_vars, 95)
                self._register_variable(prop, var_value, filename, file_vars, 90)
                self.property_accesses[prop] = var_value
        
        # Pattern 5: Simple assignments
        pattern5 = r'\b([a-zA-Z_$][a-zA-Z0-9_$]{2,})\s*=\s*["\']([^"\']{2,200})["\']'
        for match in re.finditer(pattern5, code):
            var_name = match.group(1)
            var_value = match.group(2)
            if var_name not in file_vars and not self._is_noise_value(var_value):
                self._register_variable(var_name, var_value, filename, file_vars, 70)
        
        # Pattern 6: Minified variable assignments (single/double letter)
        pattern6 = r'\b([a-z]{1,2})\s*=\s*["\']([^"\']{5,200})["\']'
        for match in re.finditer(pattern6, code):
            var_name = match.group(1)
            var_value = match.group(2)
            if self._is_url_like(var_value) and not self._is_noise_value(var_value):
                self._register_variable(var_name, var_value, filename, file_vars, 60)
        
        # Pattern 7: Object literal properties
        pattern7 = r'(\w+)\s*:\s*["\']([^"\']{3,200})["\']'
        for match in re.finditer(pattern7, code):
            key = match.group(1)
            value = match.group(2)
            if self._is_url_like(value) and not self._is_noise_value(value):
                self._register_variable(key, value, filename, file_vars, 65)

        # Pattern 8: Array items that look like URLs
        pattern8 = r'["\']([/][^"\']{3,200})["\']\s*(?:,|])'
        for match in re.finditer(pattern8, code):
            val = match.group(1)
            if self._is_url_like(val) and not self._is_noise_value(val):
                self._register_variable("ARRAY_ITEM_" + val[:10].replace('/', '_'), val, filename, file_vars, 60)
        
        self.file_variables[filename] = file_vars
        return file_vars
    
    def _extract_obfuscated_strings(self, code, filename):
        """Extract string arrays used in obfuscated code (e.g., zmed_web_app520e)"""
        # Pattern: function name(){const array=[...strings...]; return array;}
        pattern = r'function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(\s*\)\s*\{[^}]*const\s+\w+\s*=\s*\[([^\]]+)\]'
        
        for match in re.finditer(pattern, code, re.DOTALL):
            func_name = match.group(1)
            array_content = match.group(2)
            
            # Extract all strings from the array
            string_pattern = r'["\']([^"\']+)["\']'
            strings = re.findall(string_pattern, array_content)
            
            # Store strings with their indices
            for idx, string in enumerate(strings):
                if self._is_url_like(string) and not self._is_noise_value(string):
                    key = f"{func_name}_{idx}"
                    self.obfuscated_strings[key] = string
    
    def _is_noise_value(self, value):
        """Check if value is noise - VERY LENIENT"""
        v = value.lower()
        
        # Only check most obvious noise
        for keyword in NOISE_KEYWORDS:
            if keyword in v:
                return True
        
        # Very short strings that aren't paths
        if len(value) < 2:
            return True
        
        return False
    
    def _register_variable(self, var_name, var_value, filename, file_vars, confidence):
        """Register a variable with confidence scoring"""
        # Minimal validation
        for pattern in BASE_URL_BLACKLIST:
            if re.search(pattern, var_value, re.IGNORECASE):
                return
        
        file_vars[var_name] = var_value
        
        if var_name not in self.variables or self.variables[var_name]['confidence'] < confidence:
            self.variables[var_name] = {
                'value': var_value,
                'source_file': filename,
                'confidence': confidence
            }
        
        # Store potential base URLs (very lenient)
        if self._could_be_base_url(var_value):
            self.potential_bases[var_name] = var_value
        
        # Store confirmed base URLs
        if self._is_base_url(var_value):
            self.global_scope[var_name] = var_value
    
    def _is_url_like(self, value):
        """Check if value looks like a URL or endpoint - VERY LENIENT"""
        if len(value) < 2:
            return False
        # Accept anything that starts with / or http, or contains API terms
        return (
            value.startswith('http') or 
            value.startswith('/') or
            any(term in value.lower() for term in ['api', 'endpoint', 'service', 'rest', 'graphql', 
                                                    'lab', 'report', 'patient', 'fetch', 'data',
                                                    'internal', 'his', 'pdf', 'zmedia'])
        )
    
    def _could_be_base_url(self, value):
        """Check if this could potentially be a base URL - VERY LENIENT"""
        if len(value) < 3:
            return False
        
        if not (value.startswith('http') or value.startswith('/')):
            return False
        
        # Minimal blacklist check
        for pattern in BASE_URL_BLACKLIST:
            if re.search(pattern, value, re.IGNORECASE):
                return False
        
        return True
    
    def _is_base_url(self, value):
        """Check if this looks like a base URL"""
        for pattern in BASE_URL_BLACKLIST:
            if re.search(pattern, value, re.IGNORECASE):
                return False
        
        if len(value) < 5:
            return False
        
        if not (value.startswith('http') or value.startswith('/')):
            return False
        
        # More lenient patterns
        patterns = [
            r'^https?://[^/]+',
            r'^/',
        ]
        
        return any(re.search(p, value) for p in patterns)
    
    def resolve(self, var_name):
        """Resolve a variable name to its value"""
        # Check direct variables
        if var_name in self.variables:
            return self.variables[var_name]['value']
        
        # Check property accesses (this.url, etc)
        if var_name in self.property_accesses:
            return self.property_accesses[var_name]
        
        return None
    
    def resolve_with_fallback(self, var_name):
        """Resolve variable with multiple fallback strategies"""
        # Try multiple resolution strategies
        if var_name in self.global_scope:
            return self.global_scope[var_name]
        if var_name in self.potential_bases:
            return self.potential_bases[var_name]
        if var_name in self.variables:
            return self.variables[var_name]['value']
        if var_name in self.property_accesses:
            return self.property_accesses[var_name]
        
        # Try with 'this.' prefix
        if f"this.{var_name}" in self.variables:
            return self.variables[f"this.{var_name}"]['value']
        
        # Try common property names
        for prop in ['url', 'serverURL', 'baseURL', 'apiURL']:
            if var_name == prop and prop in self.property_accesses:
                return self.property_accesses[prop]
        
        return None
    
    def get_all_base_urls(self):
        """Get all potential base URLs found"""
        return {**self.global_scope, **self.potential_bases, **self.property_accesses}

# ==============================================================================
# CLASS: AGGRESSIVE RPC PATTERN EXTRACTOR - ENHANCED FOR LAB ENDPOINTS
# ==============================================================================
class AggressiveRPCExtractor:
    """Extracts ALL RPC-style endpoint definitions with lab endpoint support"""
    
    def __init__(self, resolver):
        self.resolver = resolver
        self.endpoints = []
    
    def extract_rpc_patterns(self, code, filename):
        """Extract ALL RPC concatenation patterns - handles obfuscated code"""
        found = []
        
        # Pattern 1: Object property with concatenation (key: var + "endpoint")
        pattern1 = r'(\w+)\s*:\s*([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*\+\s*["\']([^"\']+)["\']'
        for match in re.finditer(pattern1, code):
            key = match.group(1)
            var_name = match.group(2)
            endpoint_suffix = match.group(3)
            
            if self._is_noise(var_name, endpoint_suffix):
                continue
            
            base_url = self.resolver.resolve_with_fallback(var_name)
            
            if base_url:
                full_endpoint = base_url + endpoint_suffix
                if self._is_valid_endpoint(full_endpoint):
                    method = self._guess_method_from_key(key)
                    
                    found.append({
                        'endpoint': full_endpoint,
                        'method': method,
                        'pattern': f'{var_name} + "{endpoint_suffix}"',
                        'key': key,
                        'type': 'RPC_OBJECT_PROPERTY',
                        'source': filename,
                        'classification': 'RPC_ENDPOINT',
                        'confidence': 95
                    })
        
        # Pattern 2: Variable assignment with concatenation (url = base + "path")
        pattern2 = r'(?:var|let|const)?\s*(\w+)\s*=\s*([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*\+\s*["\']([^"\']+)["\']'
        for match in re.finditer(pattern2, code):
            result_var = match.group(1)
            base_var = match.group(2)
            suffix = match.group(3)
            
            if self._is_noise(base_var, suffix):
                continue
            
            base_url = self.resolver.resolve_with_fallback(base_var)
            
            if base_url:
                full_endpoint = base_url + suffix
                if self._is_valid_endpoint(full_endpoint):
                    found.append({
                        'endpoint': full_endpoint,
                        'method': 'GET',
                        'pattern': f'{base_var} + "{suffix}"',
                        'type': 'RPC_VARIABLE_CONCAT',
                        'source': filename,
                        'classification': 'RPC_ENDPOINT',
                        'confidence': 90
                    })
        
        # Pattern 3: Template literals (`${base}path`)
        pattern3 = r'`\$\{([a-zA-Z_$][a-zA-Z0-9_$.]*)\}([^`]+)`'
        for match in re.finditer(pattern3, code):
            var_name = match.group(1)
            suffix = match.group(2)
            
            if self._is_noise(var_name, suffix):
                continue
            
            base_url = self.resolver.resolve_with_fallback(var_name)
            
            if base_url:
                full_endpoint = base_url + suffix
                if self._is_valid_endpoint(full_endpoint):
                    found.append({
                        'endpoint': full_endpoint,
                        'method': 'GET',
                        'pattern': f'`${{{var_name}}}{suffix}`',
                        'type': 'RPC_TEMPLATE_LITERAL',
                        'source': filename,
                        'classification': 'RPC_ENDPOINT',
                        'confidence': 85
                    })
        
        # Pattern 4: Method calls with concatenation
        pattern4 = r'(?:get|post|put|delete|patch|fetch|postDataFromUrl|getDataFromUrl|postDataFromUrlWithoutSerialize|getDataFromUrlAndSendData|getRawDataFromUrl)\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*\+\s*["\']([^"\']+)["\']'
        for match in re.finditer(pattern4, code, re.IGNORECASE):
            var_name = match.group(1)
            suffix = match.group(2)
            
            if self._is_noise(var_name, suffix):
                continue
            
            base_url = self.resolver.resolve_with_fallback(var_name)
            
            if base_url:
                full_endpoint = base_url + suffix
                if self._is_valid_endpoint(full_endpoint):
                    ctx_before = code[max(0, match.start()-50):match.start()]
                    method = self._extract_method_from_context(ctx_before, code[match.start():match.start()+20])
                    
                    found.append({
                        'endpoint': full_endpoint,
                        'method': method,
                        'pattern': f'{var_name} + "{suffix}"',
                        'type': 'RPC_HTTP_CALL',
                        'source': filename,
                        'classification': 'RPC_ENDPOINT',
                        'confidence': 95
                    })
        
        # Pattern 5: Chained concatenation
        pattern5 = r'([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*\+\s*["\']([^"\']+)["\']\s*\+\s*["\']([^"\']+)["\']'
        for match in re.finditer(pattern5, code):
            var_name = match.group(1)
            part1 = match.group(2)
            part2 = match.group(3)
            
            if self._is_noise(var_name, part1 + part2):
                continue
            
            base_url = self.resolver.resolve_with_fallback(var_name)
            
            if base_url:
                full_endpoint = base_url + part1 + part2
                if self._is_valid_endpoint(full_endpoint):
                    found.append({
                        'endpoint': full_endpoint,
                        'method': 'GET',
                        'pattern': f'{var_name} + "{part1}" + "{part2}"',
                        'type': 'RPC_CHAINED_CONCAT',
                        'source': filename,
                        'classification': 'RPC_ENDPOINT',
                        'confidence': 80
                    })
        
        # Pattern 6: Return statements
        pattern6 = r'return\s+([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*\+\s*["\']([^"\']+)["\']'
        for match in re.finditer(pattern6, code):
            var_name = match.group(1)
            suffix = match.group(2)
            
            if self._is_noise(var_name, suffix):
                continue
            
            base_url = self.resolver.resolve_with_fallback(var_name)
            
            if base_url:
                full_endpoint = base_url + suffix
                if self._is_valid_endpoint(full_endpoint):
                    found.append({
                        'endpoint': full_endpoint,
                        'method': 'GET',
                        'pattern': f'return {var_name} + "{suffix}"',
                        'type': 'RPC_RETURN_CONCAT',
                        'source': filename,
                        'classification': 'RPC_ENDPOINT',
                        'confidence': 85
                    })
        
        # Pattern 7: Array/Object literal with concatenation
        pattern7 = r'[\[{,]\s*([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*\+\s*["\']([^"\']+)["\']'
        for match in re.finditer(pattern7, code):
            var_name = match.group(1)
            suffix = match.group(2)
            
            if self._is_noise(var_name, suffix):
                continue
            
            base_url = self.resolver.resolve_with_fallback(var_name)
            
            if base_url:
                full_endpoint = base_url + suffix
                if self._is_valid_endpoint(full_endpoint):
                    found.append({
                        'endpoint': full_endpoint,
                        'method': 'GET',
                        'pattern': f'{var_name} + "{suffix}"',
                        'type': 'RPC_ARRAY_CONCAT',
                        'source': filename,
                        'classification': 'RPC_ENDPOINT',
                        'confidence': 80
                    })
        
        return found
    
    def _is_valid_endpoint(self, endpoint):
        """Validate if endpoint looks legitimate - VERY LENIENT for lab endpoints"""
        # Minimal noise check
        for pattern in NOISE_PATTERNS:
            if re.search(pattern, endpoint, re.IGNORECASE):
                return False
        
        endpoint_lower = endpoint.lower()
        
        # Only block most obvious noise
        if any(keyword in endpoint_lower for keyword in ['helvetica', 'arial', 'expressionchanged']):
            return False
        
        # Must look like a real endpoint
        if not (endpoint.startswith('http') or endpoint.startswith('/')):
            return False
        
        # Validate HTTP URLs
        if endpoint.startswith('http'):
            try:
                parsed = urllib.parse.urlparse(endpoint)
                if not parsed.netloc:
                    return False
            except:
                return False
        
        # VERY LENIENT - Accept many patterns especially lab-related
        if any(x in endpoint_lower for x in ['api', 'service', 'endpoint', 'rest', 'graphql',
                                                'lab', 'report', 'patient', 'fetch', 'data',
                                                'internal', 'pdf', 'export', 'his', 'clinical',
                                                'notification', 'forms', 'progress', 'anesthesia',
                                                'ambulance', 'vitals', 'icu', 'zmedia']):
            return True
        
        # Also accept paths that look structured
        if endpoint.startswith('/') and len(endpoint) > 3 and '/' in endpoint[1:]:
            return True
        
        return False
    
    def _is_noise(self, var_name, suffix):
        """Check if this is noise pattern - MINIMAL filtering"""
        combined = (var_name + suffix).lower()
        
        # Only check most obvious noise
        if any(keyword in combined for keyword in ['helvetica', 'arial', 'expressionchanged']):
            return True
        
        # Suffix should not be too short
        if len(suffix) < 2:
            return True
        
        return False
    
    def _guess_method_from_key(self, key):
        """Guess HTTP method from property key name"""
        k = key.lower()
        if any(x in k for x in ['get', 'fetch', 'load', 'search', 'query', 'find', 'read', 'list', 'show', 'all']):
            return 'GET'
        elif any(x in k for x in ['post', 'create', 'add', 'insert', 'new', 'submit', 'send']):
            return 'POST'
        elif any(x in k for x in ['put', 'update', 'modify', 'edit', 'change', 'save']):
            return 'PUT'
        elif any(x in k for x in ['delete', 'remove', 'destroy', 'drop']):
            return 'DELETE'
        elif any(x in k for x in ['patch']):
            return 'PATCH'
        return 'GET'
    
    def _extract_method_from_context(self, before, after):
        """Extract HTTP method from surrounding context"""
        combined = (before + after).upper()
        
        for method in ['POST', 'PUT', 'DELETE', 'PATCH', 'GET']:
            if method in combined:
                return method
        
        return 'GET'

# ==============================================================================
# ENHANCED STATIC ANALYZER
# ==============================================================================
class EnhancedStaticAnalyzer:
    def __init__(self, session, base_url):
        self.session = session
        self.base_url = base_url
        self.normalizer = URLNormalizer(base_url)
        self.endpoints = []
        self.confidence_scores = defaultdict(int)
        self.resolver = AggressiveVariableResolver()
        self.rpc_extractor = AggressiveRPCExtractor(self.resolver)

    def scan(self, js_urls, json_urls):
        print(f"\n[PHASE 2] Enhanced Analysis for Lab Endpoints")
        print(f"  Processing: {len(js_urls)} JS files, {len(json_urls)} JSON configs")
        
        # STEP 1: Extract ALL variables
        print(f"\n  [Step 1/3] Extracting variables...")
        js_contents = {}
        
        for i, url in enumerate(js_urls, 1):
            if i % 10 == 0:
                print(f"    Progress: [{i}/{len(js_urls)}]", end='\r')
            
            if any(x in url.lower() for x in LOW_VALUE_JS):
                continue
                
            try:
                r = self.session.get(url, timeout=10)
                if r.status_code == 200:
                    filename = url.split('/')[-1]
                    js_contents[url] = r.text
                    self.resolver.extract_all_variables(r.text, filename)
            except:
                pass
        
        print(f"\n    ✓ Extracted {len(self.resolver.variables)} unique variables")
        print(f"    ✓ Found {len(self.resolver.get_all_base_urls())} potential base URLs")
        
        # Show discovered base URLs
        if self.resolver.get_all_base_urls():
            print(f"\n  [Discovered Base URLs]")
            base_urls = self.resolver.get_all_base_urls()
            for var, url in list(base_urls.items())[:20]:
                print(f"    {var} = {url}")
        
        # STEP 2: Extract RPC patterns
        print(f"\n  [Step 2/3] Extracting RPC patterns...")
        rpc_count = 0
        
        for url, code in js_contents.items():
            filename = url.split('/')[-1]
            rpc_endpoints = self.rpc_extractor.extract_rpc_patterns(code, filename)
            
            for ep in rpc_endpoints:
                full_url = self.normalizer.normalize(ep['endpoint'])
                
                self.add_endpoint(
                    full_url, 
                    ep['method'], 
                    [], 
                    ep['type'], 
                    ep['source'], 
                    ep['classification'], 
                    ep['confidence']
                )
                rpc_count += 1
            
            # Check for Array Harvested Items
            for var_name, var_data in self.resolver.variables.items():
                if var_name.startswith("ARRAY_ITEM_"):
                     full_url = self.normalizer.normalize(var_data['value'])
                     self.add_endpoint(
                        full_url, 
                        "GET", 
                        [], 
                        "ARRAY_HARVEST", 
                        var_data['source_file'], 
                        "BACKEND_API", 
                        60
                      )

        print(f"    ✓ Found {rpc_count} RPC-style endpoints")
        
        # STEP 3: Standard analysis
        print(f"\n  [Step 3/3] Standard endpoint analysis...")
        
        for json_url in json_urls:
            self.analyze_json_config(json_url)
        
        for url, code in js_contents.items():
            self.analyze_code(code, url)
        
        print(f"\n  ✓ Total endpoints discovered: {len(self.endpoints)}")
        
        # STEP 4: Show lab-related endpoints found
        lab_endpoints = [e for e in self.endpoints if any(term in e['endpoint'].lower() 
                         for term in ['lab', 'report', 'test', 'patient'])]
        if lab_endpoints:
            print(f"\n  🔬 Lab-Related Endpoints Found: {len(lab_endpoints)}")
            for e in lab_endpoints[:15]:
                print(f"    [{e['method']}] {e['endpoint']}")
        
        return self.endpoints

    def analyze_json_config(self, json_url):
        """Extract ALL string values from JSON config files"""
        try:
            r = self.session.get(json_url, timeout=10)
            if r.status_code != 200:
                return
            
            data = r.json()
            filename = json_url.split('/')[-1]
            
            self._extract_from_json(data, filename, json_url)
            
        except:
            pass

    def _extract_from_json(self, data, filename, source_url, path=''):
        """Recursively extract ALL string values from JSON"""
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                
                if isinstance(value, str):
                    if len(value) > 3 and not value.isspace():
                        method = self._guess_method_from_key(key)
                        classification = self._classify_json_value(value, key)
                        
                        if classification != "NOISE":
                            full_url = self.normalizer.normalize(value)
                            
                            self.add_endpoint(
                                full_url, 
                                method, 
                                [], 
                                "JSON_CONFIG", 
                                filename, 
                                classification, 
                                75
                            )
                        
                elif isinstance(value, (dict, list)):
                    self._extract_from_json(value, filename, source_url, current_path)
                    
        elif isinstance(data, list):
            for i, item in enumerate(data):
                if isinstance(item, (dict, list)):
                    self._extract_from_json(item, filename, source_url, f"{path}[{i}]")

    def _classify_json_value(self, value, key):
        """Determine if a JSON string value is an endpoint - VERY LENIENT"""
        v = value.lower()
        k = key.lower()
        
        # Check for obvious noise
        for keyword in NOISE_KEYWORDS:
            if keyword in v:
                return "NOISE"
        
        if any(re.search(p, value) for p in NOISE_PATTERNS):
            return "NOISE"
        
        # Check API indicators - EXPANDED
        if any(re.search(p, value, re.IGNORECASE) for p in API_INDICATORS):
            return "BACKEND_API"
        
        # Key-based detection
        api_key_indicators = ['api', 'endpoint', 'url', 'service', 'path', 'route', 'lab', 'report']
        if any(ind in k for ind in api_key_indicators):
            if value.startswith('/') or value.startswith('http'):
                return "BACKEND_API"
        
        # External URLs
        if value.startswith('http'):
            if not any(d in v for d in IGNORED_DOMAINS):
                return "EXTERNAL_API"
        
        # Path-like strings
        if value.startswith('/') and len(value) > 3:
            if '/' in value[1:]:
                return "BACKEND_API"
        
        return "NOISE"

    def _guess_method_from_key(self, key):
        """Guess HTTP method from key name"""
        k = key.lower()
        if any(x in k for x in ['get', 'fetch', 'load', 'search', 'query', 'find', 'read', 'list', 'show', 'view', 'all']):
            return 'GET'
        elif any(x in k for x in ['post', 'create', 'add', 'insert', 'new', 'submit', 'send']):
            return 'POST'
        elif any(x in k for x in ['put', 'update', 'modify', 'edit', 'change', 'save']):
            return 'PUT'
        elif any(x in k for x in ['delete', 'remove', 'destroy', 'drop']):
            return 'DELETE'
        return 'GET'

    def analyze_code(self, code, source):
        """Analyze JavaScript code for endpoints"""
        if any(x in source.lower() for x in LOW_VALUE_JS):
            return

        # Angular HTTP
        for m in re.finditer(r'(?:this\.)?(?:http|httpclient)\.(get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]+)', code, re.IGNORECASE):
            full_url = self.normalizer.normalize(m.group(2))
            self.process(full_url, m.group(1).upper(), m.start(), code, source, "ANGULAR_HTTP", "BACKEND_API", 90)

        # Router
        for m in re.finditer(r'\.navigate(?:ByUrl)?\s*\(\s*[\'"`]([^\'"`]+)', code, re.IGNORECASE):
            full_url = self.normalizer.normalize(m.group(1))
            self.process(full_url, "GET", m.start(), code, source, "ANGULAR_NAV", "FRONTEND_ROUTE", 70)

        # Window.Open
        for m in re.finditer(r'window\.open\s*\(\s*[\'"]([^\'"]+)[\'"]', code, re.IGNORECASE):
            full_url = self.normalizer.normalize(m.group(1))
            self.process(full_url, "GET", m.start(), code, source, "WINDOW_OPEN", "OPEN_REDIRECT_SINK", 90)

        # String literals with API patterns - VERY LENIENT
        for m in re.finditer(r'["\']([/][^\'"]{3,200})["\']', code):
            url = m.group(1)
            if self.has_api_pattern(url):
                cls = self.classify(url)
                if cls != "NOISE":
                    full_url = self.normalizer.normalize(url)
                    self.process(full_url, self.detect_method(code, m.start()), m.start(), code, source, "STATIC_CODE", cls, 50)

    def process(self, url, method, pos, code, source, type, classification, confidence):
        if self.is_valid(url):
            params = self.extract_params(code, pos + len(url))
            self.add_endpoint(url, method, params, type, source, classification, confidence)

    def add_endpoint(self, url, method, params, type, source, classification, confidence):
        # Minimal noise check
        url_lower = url.lower()
        for keyword in NOISE_KEYWORDS:
            if keyword in url_lower:
                return
        
        if any(re.search(p, url) for p in NOISE_PATTERNS):
            return
        
        # Check for duplicates
        for e in self.endpoints:
            if e['endpoint'] == url and e['method'] == method:
                e['parameters'] = list(set(e['parameters'] + params))
                if confidence > self.confidence_scores.get(f"{method}:{url}", 0):
                    e['type'] = type
                    e['classification'] = classification
                    self.confidence_scores[f"{method}:{url}"] = confidence
                return
        
        self.endpoints.append({
            "endpoint": url, 
            "method": method, 
            "parameters": params, 
            "type": type, 
            "source": source if isinstance(source, str) else source.split('/')[-1][:80],
            "classification": classification
        })
        self.confidence_scores[f"{method}:{url}"] = confidence

    def is_valid(self, url):
        """Validate URL - VERY LENIENT"""
        url = url.strip()
        if len(url) < 3 or ' ' in url: 
            return False
        
        url_lower = url.lower()
        for keyword in NOISE_KEYWORDS:
            if keyword in url_lower:
                return False
        
        if any(b in url.lower() for b in STRICT_BLOCKS): 
            return False
        
        for p in FALSE_POSITIVE_PATTERNS:
            if re.search(p, url, re.IGNORECASE): 
                return False
        
        if url.lower().endswith(('.js', '.css', '.png', '.svg', '.woff', '.jpg', '.jpeg', '.gif', '.ico')):
            return False
        
        return True

    def has_api_pattern(self, url):
        """Check for API patterns - EXPANDED"""
        return any(re.search(p, url, re.IGNORECASE) for p in API_INDICATORS)

    def classify(self, url):
        """Classify endpoint type - LENIENT"""
        u = url.lower()
        if self.has_api_pattern(url): 
            return "BACKEND_API"
        if any(x in u for x in ['/login', '/dashboard', '/profile', '/#/', '/admin']): 
            return "FRONTEND_ROUTE"
        if u.startswith('http'): 
            return "EXTERNAL_API" if not any(d in u for d in IGNORED_DOMAINS) else "NOISE"
        # Accept paths by default
        if u.startswith('/') and len(u) > 3:
            return "BACKEND_API"
        return "NOISE"

    def detect_method(self, code, pos):
        """Detect HTTP method from context"""
        ctx = code[max(0, pos-200):min(len(code), pos+200)].upper()
        for m in ["POST", "PUT", "DELETE", "PATCH"]:
            if m in ctx: 
                return m
        return "GET"

    def extract_params(self, code, pos):
        """Extract parameter names"""
        ctx = code[pos:pos+500]
        matches = re.findall(r'[{,]\s*["\']?([a-zA-Z0-9_]{2,20})["\']?\s*:', ctx)
        
        blacklist = {
            'var', 'let', 'const', 'if', 'else', 'true', 'false', 'null', 'this', 'return',
            'switch', 'case', 'default', 'break', 'function', 'class', 'typeof', 'void',
            'undefined', 'new', 'delete', 'in', 'instanceof', 'do', 'while', 'for', 'try',
            'catch', 'finally', 'throw', 'export', 'import', 'from', 'as', 'async', 'await'
        }
        
        clean = []
        for p in matches:
            if p.lower() not in blacklist:
                if len(p) > 2:
                    clean.append(p)
        
        return sorted(list(set(clean)))[:8]

# ==============================================================================
# URL NORMALIZER
# ==============================================================================
class URLNormalizer:
    """Normalizes endpoints to complete URLs"""
    
    def __init__(self, base_url):
        self.base_url = base_url
        parsed = urllib.parse.urlparse(base_url)
        self.scheme = parsed.scheme
        self.netloc = parsed.netloc
    
    def normalize(self, endpoint):
        """Convert endpoint to complete URL"""
        if endpoint.startswith('http://') or endpoint.startswith('https://'):
            return endpoint
        
        if endpoint.startswith('//'):
            return f'{self.scheme}:{endpoint}'
        
        if endpoint.startswith('/'):
            return f'{self.scheme}://{self.netloc}{endpoint}'
        
        return f'{self.scheme}://{self.netloc}/{endpoint}'

# ==============================================================================
# ENHANCED FEDERATION HUNTER (Unchanged - works well)
# ==============================================================================
class EnhancedFederationHunter:
    def __init__(self, session, target_url):
        self.session = session
        self.target_url = target_url
        self.base_url = f"{urllib.parse.urlparse(target_url).scheme}://{urllib.parse.urlparse(target_url).netloc}"
        self.found_js_files = set()
        self.found_json_files = set()
        self.scan_queue = deque()

    def run(self):
        print(f"\n[PHASE 1] Discovery (JS + JSON)")
        
        self.check_config_files()
        self.crawl_html()

        print(f"  Deep scanning...")
        processed_files = set()
        
        while self.scan_queue:
            url = self.scan_queue.popleft()
            if url in processed_files: 
                continue
            processed_files.add(url)
            
            if any(x in url.lower() for x in LOW_VALUE_JS): 
                continue

            try:
                r = self.session.get(url, timeout=10)
                if r.status_code == 200:
                    self.hunt_webpack_chunks(r.text, url)
                    self.hunt_config_references(r.text, url)
            except: 
                pass

        print(f"  ✓ JS: {len(self.found_js_files)}, JSON: {len(self.found_json_files)}")
        return list(self.found_js_files), list(self.found_json_files)

    def check_config_files(self):
        """Check common config file locations"""
        config_paths = [
            '/assets/config/environment.json',
            '/assets/config/config.json',
            '/config/environment.json',
            '/environment.json',
            '/config.json',
        ]
        
        for path in config_paths:
            url = urllib.parse.urljoin(self.base_url, path)
            try:
                r = self.session.get(url, timeout=8)
                if r.status_code == 200:
                    try:
                        r.json()
                        self.found_json_files.add(url)
                    except:
                        pass
            except:
                pass

    def hunt_config_references(self, code, source_url):
        """Extract JSON file references from JS code"""
        json_refs = re.findall(r'["\']([^"\']+\.json)["\']', code)
        base = source_url.rsplit('/', 1)[0] + '/'
        
        for ref in json_refs:
            if any(x in ref.lower() for x in ['sourcemap', 'webpack']):
                continue
            
            if ref.startswith('http'):
                full_url = ref
            elif ref.startswith('/'):
                full_url = urllib.parse.urljoin(self.base_url, ref)
            else:
                full_url = urllib.parse.urljoin(base, ref.lstrip('./'))
            
            if self.base_url in full_url and full_url not in self.found_json_files:
                try:
                    r = self.session.get(full_url, timeout=5)
                    if r.status_code == 200:
                        try:
                            r.json()
                            self.found_json_files.add(full_url)
                        except:
                            pass
                except:
                    pass

    def crawl_html(self):
        """Crawl HTML for script tags"""
        try:
            r = self.session.get(self.target_url, timeout=15)
            soup = BeautifulSoup(r.text, 'html.parser')
            for s in soup.find_all('script', src=True):
                url = urllib.parse.urljoin(self.target_url, s['src'])
                if not any(b in url for b in IGNORED_DOMAINS):
                    if url not in self.found_js_files:
                        self.found_js_files.add(url)
                        self.scan_queue.append(url)
        except: 
            pass

    def hunt_webpack_chunks(self, code, source_url):
        """Hunt for webpack chunk patterns"""
        suffix_match = re.search(r'\)\s*\+\s*["\']([^"\']+\.js)["\']', code)
        if suffix_match:
            suffix = suffix_match.group(1)
            candidates = re.finditer(r'["\']([\w-]+)["\']\s*:\s*["\']([^"\']+)["\']', code)
            base_url = source_url.rsplit('/', 1)[0] + '/'
            
            for match in candidates:
                val = match.group(2)
                if len(val) < 2 or len(val) > 100 or ' ' in val: 
                    continue
                clean_val = val.lstrip('./')
                if clean_val.startswith('/'):
                    full_chunk_url = urllib.parse.urljoin(self.base_url, clean_val + suffix)
                else:
                    full_chunk_url = urllib.parse.urljoin(base_url, clean_val + suffix)
                
                if full_chunk_url not in self.found_js_files:
                    self.found_js_files.add(full_chunk_url)
                    self.scan_queue.append(full_chunk_url)

# ==============================================================================
# DYNAMIC INTERCEPTOR (Unchanged)
# ==============================================================================
class DynamicInterceptor:
    def __init__(self, target_url, cookies=None):
        self.target_url = target_url
        self.domain = urllib.parse.urlparse(target_url).netloc
        self.base_url = f"{urllib.parse.urlparse(target_url).scheme}://{urllib.parse.urlparse(target_url).netloc}"
        self.cookies = cookies
        self.endpoints = []
        self.seen = set()

    def run(self, static_endpoints=[]):
        if not PLAYWRIGHT_AVAILABLE: 
            print(f"\n[PHASE 3] Playwright not available - skipping")
            return []
            
        print(f"\n[PHASE 3] Dynamic Interception")
        
        routes = [self.target_url]
        
        for e in static_endpoints:
            if e['classification'] == 'FRONTEND_ROUTE' and e['endpoint'].startswith('/'):
                clean = re.sub(r':[a-zA-Z0-9_]+', '1', e['endpoint'])
                full = urllib.parse.urljoin(self.base_url, clean)
                if full not in routes: 
                    routes.append(full)
        
        routes = routes[:10]
        print(f"  Visiting {len(routes)} routes...")

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)
            if self.cookies:
                context.add_cookies([
                    {"name": k, "value": v, "domain": self.domain, "path": "/"} 
                    for k, v in self.cookies.items()
                ])

            context.on("request", self.handle_request)
            page = context.new_page()
            
            for i, route in enumerate(routes, 1):
                print(f"    [{i}/{len(routes)}] {route}", end='\r')
                try:
                    page.goto(route, wait_until="networkidle", timeout=12000)
                    time.sleep(0.5)
                except:
                    pass
            
            browser.close()
        
        print(f"\n  ✓ Captured {len(self.endpoints)} requests")
        return self.endpoints

    def handle_request(self, req):
        url = req.url
        if any(b in url for b in IGNORED_DOMAINS): 
            return
        if re.search(r'\.(js|css|png|jpg|svg|ico|woff|map)(\?|$)', url): 
            return
        if url in self.seen: 
            return
        
        self.seen.add(url)
        
        params = []
        try:
            if req.post_data and "json" in req.headers.get("content-type", ""):
                body = json.loads(req.post_data)
                if isinstance(body, dict): 
                    params.extend(body.keys())
            parsed = urllib.parse.urlparse(url)
            if parsed.query: 
                params.extend(urllib.parse.parse_qs(parsed.query).keys())
        except: 
            pass
        
        self.endpoints.append({
            "endpoint": url.split('?')[0], 
            "method": req.method, 
            "parameters": list(set(params)), 
            "type": "DYNAMIC_RUNTIME", 
            "source": "Browser", 
            "classification": "VERIFIED_API"
        })

# ==============================================================================
# REPORT GENERATION & EXCEL CONVERSION
# ==============================================================================
def json_to_excel(input_file, output_file):
    """Converts JSON report to Excel format"""
    if not PANDAS_AVAILABLE:
        print("\n⚠️  Pandas not installed. Skipping Excel conversion.")
        return

    current_dir = os.getcwd()
    input_path = os.path.join(current_dir, input_file)
    output_path = os.path.join(current_dir, output_file)

    print(f"\n[PHASE 5] Excel Conversion")
    print(f"📂 Work Dir: {current_dir}")
    
    if not os.path.exists(input_path):
        print(f"❌ ERROR: Input file '{input_file}' not found.")
        return

    try:
        with open(input_path, 'r') as f:
            data = json.load(f)
        
        endpoints = data.get('endpoints', []) if isinstance(data, dict) else data
        rows = []
        
        for item in endpoints:
            params = item.get('parameters', [])
            params_formatted = ", ".join(params) if isinstance(params, list) else str(params)
            
            rows.append({
                "Endpoint": item.get('endpoint', ''),
                "Method": item.get('method', 'GET'),
                "Parameters": params_formatted,
                "Source File": item.get('source', 'Unknown'),
                "Type": item.get('type', '')
            })
            
        df = pd.DataFrame(rows)
        
        with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='API_Endpoints')
            worksheet = writer.sheets['API_Endpoints']
            for column in df:
                col_idx = df.columns.get_loc(column) + 1
                worksheet.column_dimensions[chr(64 + col_idx)].width = 25 
        
        print(f"✅ SUCCESS! Created: {output_file}")
        
    except Exception as e:
        print(f"❌ ERROR Converting to Excel: {str(e)}")

def save_report(static, dynamic, filename="results.json"):
    print(f"\n[PHASE 4] Generating Report")
    
    combined = {}
    for item in static + dynamic:
        key = f"{item['method']}:{item['endpoint']}"
        if key not in combined: 
            combined[key] = item
        else:
            combined[key]['parameters'] = list(set(combined[key]['parameters'] + item['parameters']))
            if item['type'] == 'DYNAMIC_RUNTIME': 
                combined[key]['type'] = 'DYNAMIC_RUNTIME'
                combined[key]['classification'] = 'VERIFIED_API'

    results = [x for x in combined.values() if x['classification'] != "NOISE"]
    
    # Sort with RPC endpoints first
    results.sort(key=lambda x: (
        {
            "RPC_ENDPOINT": 0,
            "VERIFIED_API": 1, 
            "BACKEND_API": 2, 
            "JSON_CONFIG": 3,
            "OPEN_REDIRECT_SINK": 4,
            "FRONTEND_ROUTE": 5,
            "EXTERNAL_API": 6
        }.get(x['classification'], 7), 
        x['endpoint']
    ))

    # Count endpoints by type
    rpc_endpoints = [e for e in results if e['classification'] == 'RPC_ENDPOINT']
    lab_endpoints = [e for e in results if any(term in e['endpoint'].lower() 
                      for term in ['lab', 'report', 'test', 'notification'])]
    
    report = {
        "scan_metadata": {
            "scanner_version": "v10.1 - Lab Reports & Obfuscation Fix",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_endpoints": len(results)
        },
        "summary": {
            "rpc_patterns": len(rpc_endpoints),
            "lab_related": len(lab_endpoints),
            "verified": len([x for x in results if x['classification'] == "VERIFIED_API"]),
            "backend": len([x for x in results if x['classification'] == "BACKEND_API"]),
            "json_config": len([x for x in results if x['type'] == "JSON_CONFIG"]),
            "frontend": len([x for x in results if x['classification'] == "FRONTEND_ROUTE"]),
            "sinks": len([x for x in results if x['classification'] == "OPEN_REDIRECT_SINK"])
        },
        "endpoints": results
    }

    with open(filename, "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"\n{'='*70}")
    print(f"SCAN COMPLETE - LAB ENDPOINTS DETECTION")
    print(f"{'='*70}")
    print(f"  Total Endpoints:      {len(results)}")
    print(f"  🔥 RPC Patterns:      {report['summary']['rpc_patterns']}")
    print(f"  🔬 Lab-Related:       {report['summary']['lab_related']}")
    print(f"  Verified APIs:        {report['summary']['verified']}")
    print(f"  Backend APIs:         {report['summary']['backend']}")
    print(f"  JSON Configs:         {report['summary']['json_config']}")
    print(f"  Frontend Routes:      {report['summary']['frontend']}")
    
    # Show lab endpoints
    if lab_endpoints:
        print(f"\n🔬 Lab-Related Endpoints:")
        for e in lab_endpoints[:30]:
            print(f"  [{e['method']}] {e['endpoint']}")
    else:
        print(f"\n⚠️  No lab endpoints found!")
    
    print(f"\n📁 JSON saved: {filename}")
    
    # Trigger Excel conversion
    json_to_excel(filename, 'results.xlsx')

# ==============================================================================
# MAIN
# ==============================================================================
if __name__ == "__main__":
    print("=" * 70)
    print("ENHANCED API SCANNER v10.1 - Lab Reports Fix")
    print("Handles obfuscated code & finds all lab endpoints")
    print("=" * 70 + "\n")
    
    try:
        target = input("Target URL: ").strip()
        if not target: 
            print("❌ No URL provided")
            sys.exit(1)
        
        if not target.startswith("http"): 
            target = "https://" + target
        
        cookies = {}
        cookie_choice = input("Add cookies? (y/n): ").strip().lower()
        if cookie_choice == 'y':
            print("Enter cookies (press Enter with empty name to finish):")
            while True:
                name = input("  Cookie name: ").strip()
                if not name: 
                    break
                value = input("  Cookie value: ").strip()
                cookies[name] = value
        
        session = requests.Session()
        session.cookies.update(cookies)
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        start_time = time.time()
        
        print("\n" + "="*70)
        print("STARTING SCAN")
        print("="*70)
        
        hunter = EnhancedFederationHunter(session, target)
        js_files, json_files = hunter.run()
        
        analyzer = EnhancedStaticAnalyzer(session, target)
        static_endpoints = analyzer.scan(js_files, json_files)
        
        interceptor = DynamicInterceptor(target, cookies)
        dynamic_endpoints = interceptor.run(static_endpoints)
        
        elapsed = time.time() - start_time
        print(f"\n⏱️  Total scan time: {elapsed:.1f}s")
        
        # Changed to save to results.json
        save_report(static_endpoints, dynamic_endpoints, "results.json")
        
    except KeyboardInterrupt:
        print("\n\n❌ Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)