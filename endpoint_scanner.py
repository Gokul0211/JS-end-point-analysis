#!/usr/bin/env python3
"""
Advanced Endpoint Scanner - Enhanced Edition
Extracts API endpoints, routes, and service configurations from JavaScript applications
with recursive lazy-loading discovery and advanced SPA support

Key Improvements:
1. Recursive feedback loop for lazy-loaded chunks
2. Multi-pass analysis with increasing route depth
3. Better handling of authentication redirects
4. Intelligent route prioritization
5. Enhanced webpack chunk discovery
6. Session state preservation across navigations
"""
import requests
from bs4 import BeautifulSoup
import re
import json
import urllib.parse
import time
import sys
import os
import hashlib
from collections import defaultdict, deque
import argparse

# Suppress SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
# CONFIGURATION
# ==============================================================================
IGNORED_DOMAINS = [
    "google", "facebook", "twitter", "linkedin", "sentry", "datadog", "newrelic", 
    "segment", "hotjar", "optimizely", "intercom", "cloudflare", "cloudfront", 
    "jsdelivr", "cdnjs", "unpkg", "microsoftonline", "azure", "chinacloudapi", 
    "opencagedata", "tinymce", "w3.org", "gstatic", "bootstrapcdn", "fontawesome",
    "vimeo.com", "vzaar.com"
]

NOISE_KEYWORDS = [
    'helvetica', 'arial', 'courier', 'times', 'verdana',
    '__html2canvas__', '_pseudoelement_',
    'klmnopqrstuvwxyz',
    'expressionchangedafterithasbeenchecked',
    # New: Specific garbage from real scans
    'caused by:', 'valid digit info', 'ngdirectivedef', 
    'ngpipedef', 'ngmoduledef', 'nginjectabledef', 'nginjectordef',
    'node_modules', 'sourcemap',
    # Template literals that leaked
    'animation-timing-function', 'sheet ${', 'sheet,', 'sheet[',
    # Error messages
    ' dis', ' jaj', ' jar', ' lup', ' rep', ' tup',
    # Common JS syntax
    'on_property', 'template.html'
]

BASE_URL_BLACKLIST = [
    r'w3\.org', r'xmlns', r'2000/svg', r'1999/xhtml',
    r'ExpressionChangedAfterItHasBeenCheckedError',
    r'klmnopqrstuvwxyz',
]

STRICT_BLOCKS = [
    'webpack', '__webpack', 'sourcemap',
    # CRITICAL: Block Angular framework files that leaked
    'ngdirectivedef', 'ngpipedef', 'ngmoduledef', 
    'nginjectabledef', 'nginjectordef',
    # Block template files
    'template.html',
    # Block Excel internal structures
    '/xl/worksheets/',
    # Block error message fragments
    'on_property',
]

FALSE_POSITIVE_PATTERNS = [
    r'^https?:$',
    r'w3\.org',
    r'xmlns',
    r'/1999/xhtml',
    r'/2000/svg',
    r'ExpressionChangedAfterItHasBeenCheckedError',
    r'klmnopqrstuvwxyz',
]

API_INDICATORS = [
    r'/api/', r'/v\d+/', r'/odata/', r'/rest/', r'/graphql', 
    r'\.json$', r'/endpoint', r'/service', r'/rpc',
    r'/fetch', r'/get', r'/post', r'/update', r'/delete',
    r'/pdf', r'/export', r'/data',
    r'/admin', r'/user', r'/auth',
    r'/dashboard', r'/master', r'/project',
    r'^#/', r'^/#/'
]

HASH_ROUTE_PATTERNS = [
    r'["\'](/[^/]+/#/[^"\']+)["\']',
    r'["\'](#/[^"\']+)["\']',
    r'["\'](/#/[^"\']+)["\']',
]

LOW_VALUE_JS = [
    'polyfill', 'polyfills', 'core-js', 'zone.js', 
    'es2015', 'es5', 'babel', 'tslib', 'runtime'
]

NOISE_PATTERNS = [
    r'^http:-',
    r'^http:/[^/]',
    r'^https?:px',
    r'^https?://[^/]*$',
    # Template literal syntax
    r'\$\{',
    r'\{\{',
    # Unresolved variables
    r'undefined',
    r'\bnull\b',
    # Excel/internal paths
    r'/xl/worksheets/',
    # Spaces in URLs (malformed)
    r'\s',
    # Unbalanced brackets/parentheses
    r'\(\$',
    r'\?\$',
    # CRITICAL: Specific garbage from real scans
    r'caused by:',
    r'valid digit info',
    r'animation-timing-function',
    # Single letter paths (noise)
    r'/[a-z]$',
    # CSS units leaked
    r'(?:^|/)(?:px|ms|em|rem|vh|vw)$',
    # Template syntax variations
    r'\?id=\$\{',
    r':\$\{',
    # Unbalanced parentheses/brackets in path
    r'\(!',
    r'\[\w+\]$',  # Ends with [word]
    # Framework internal patterns
    r'/sheet\s',
    r'sheet\$',
    r'sheet,',
    r'sheet\[',
    r'sheet\(',
    # Partial/broken paths
    r'//\s*$',
    r':\\n',
    r'\}\\n',
]

# ==============================================================================
# CLASS: ENHANCED VARIABLE RESOLVER WITH METHOD CALL SUPPORT
# ==============================================================================
class EnhancedVariableResolver:
    """Resolves variables AND method calls including framework patterns"""
    
    def __init__(self):
        self.variables = {}
        self.file_variables = {}
        self.global_scope = {}
        self.potential_bases = {}
        self.property_accesses = {}
        self.obfuscated_strings = {}
        self.methods = {}
        self.service_properties = {}
        
        # Pre-compile regex patterns for performance
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Pre-compile regex patterns for better performance"""
        self.pattern1 = re.compile(r'(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*["\']([^"\']{2,100}?)["\']')
        self.pattern2 = re.compile(r'this\.(url|serverURL|baseURL|apiURL|apiUrl|rootUrl|baseUrl)\s*=\s*["\']([^"\']{2,100}?)["\']')
        self.pattern3 = re.compile(r"this\.(url|serverURL|baseURL|apiURL)\s*=\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\[([\"'])([a-zA-Z_$][a-zA-Z0-9_$]*)\3\]")
        self.pattern4 = re.compile(r'this\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*["\']([^"\']{2,100}?)["\']')
        self.pattern5 = re.compile(r'\b([a-zA-Z_$][a-zA-Z0-9_$]{2,})\s*=\s*["\']([^"\']{2,100}?)["\']')
        self.pattern6 = re.compile(r'\b([a-z]{1,2})\s*=\s*["\']([^"\']{5,100}?)["\']')
        self.pattern7 = re.compile(r'(\w+)\s*:\s*["\']([^"\']{3,100}?)["\']')
        self.pattern8 = re.compile(r'["\']([/][^"\']{3,100}?)["\']\s*(?:,|])')
        
    def extract_all_variables(self, code, filename):
        """Extract ALL variables, methods, and service properties"""
        file_vars = {}
        
        # STEP 1: Extract method definitions FIRST
        self._extract_method_definitions(code, filename)
        
        # STEP 2: Extract obfuscated string arrays
        self._extract_obfuscated_strings(code, filename)
        
        # STEP 3: Extract service properties
        self._extract_service_properties(code, filename, file_vars)
        
        # STEP 4: Extract regular variable patterns using pre-compiled patterns
        
        # Pattern 1: var/let/const declarations
        for match in self.pattern1.finditer(code):
            var_name = match.group(1)
            var_value = match.group(2)
            if not self._is_noise_value(var_value):
                self._register_variable(var_name, var_value, filename, file_vars, 90)
        
        # Pattern 2: this.url = ... or this.serverURL = ...
        for match in self.pattern2.finditer(code):
            prop = match.group(1)
            var_value = match.group(2)
            if not self._is_noise_value(var_value):
                self._register_variable(f"this.{prop}", var_value, filename, file_vars, 98)
                self._register_variable(prop, var_value, filename, file_vars, 95)
                self.property_accesses[prop] = var_value
        
        # Pattern 3: this.url = someObj.serverURL or this.url = config.url
        for match in self.pattern3.finditer(code):
            prop = match.group(1)
            source_obj = match.group(2)
            source_prop = match.group(4)
            self.property_accesses[prop] = f"{source_obj}.{source_prop}"
        
        # Pattern 4: Object property assignments (this.prop = value)
        for match in self.pattern4.finditer(code):
            prop = match.group(1)
            var_value = match.group(2)
            if not self._is_noise_value(var_value):
                self._register_variable(f"this.{prop}", var_value, filename, file_vars, 95)
                self._register_variable(prop, var_value, filename, file_vars, 90)
                self.property_accesses[prop] = var_value
        
        # Pattern 5: Simple assignments
        for match in self.pattern5.finditer(code):
            var_name = match.group(1)
            var_value = match.group(2)
            if var_name not in file_vars and not self._is_noise_value(var_value):
                self._register_variable(var_name, var_value, filename, file_vars, 70)
        
        # Pattern 6: Minified variable assignments (single/double letter)
        for match in self.pattern6.finditer(code):
            var_name = match.group(1)
            var_value = match.group(2)
            if self._is_url_like(var_value) and not self._is_noise_value(var_value):
                self._register_variable(var_name, var_value, filename, file_vars, 60)
        
        # Pattern 7: Object literal properties
        for match in self.pattern7.finditer(code):
            key = match.group(1)
            value = match.group(2)
            if self._is_url_like(value) and not self._is_noise_value(value):
                self._register_variable(key, value, filename, file_vars, 65)

        # Pattern 8: Array items that look like URLs (FIXED - using hash instead of truncation)
        for match in self.pattern8.finditer(code):
            val = match.group(1)
            if self._is_url_like(val) and not self._is_noise_value(val):
                # FIXED: Use hash to avoid key collisions
                val_hash = hashlib.md5(val.encode()).hexdigest()[:8]
                self._register_variable(f"ARRAY_ITEM_{val_hash}", val, filename, file_vars, 60)
        
        self.file_variables[filename] = file_vars
        return file_vars
    
    def _extract_method_definitions(self, code, filename):
        """Extract method definitions and their return values"""
        # Pattern 1: methodName(){return "value"} - Made more flexible to handle nested braces
        pattern1 = re.compile(r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(\s*\)\s*\{(?:[^{}]|\{[^}]*\})*return\s+["\']([^"\']+)["\']', re.DOTALL)
        for match in pattern1.finditer(code):
            method_name = match.group(1)
            return_value = match.group(2)
            if self._is_url_like(return_value):
                self.methods[method_name] = return_value
                self.methods[f"this.{method_name}"] = return_value
        
        # Pattern 2: methodName(){return condition ? "val1" : "val2"}
        pattern2 = re.compile(r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(\s*\)\s*\{(?:[^{}]|\{[^}]*\})*return[^}]+\?[^:]+:(?:[^}]|\{[^}]*\})*["\']([^"\']+)["\']', re.DOTALL)
        for match in pattern2.finditer(code):
            method_name = match.group(1)
            # Extract all string literals from the ternary
            ternary_section = code[match.start():match.end()]
            strings = re.findall(r'["\']([^"\']+)["\']', ternary_section)
            for s in strings:
                if self._is_url_like(s):
                    self.methods[method_name] = s
                    self.methods[f"this.{method_name}"] = s
                    break
        
        # Pattern 3: methodName(){...return location.origin + "/api"}
        pattern3 = re.compile(r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(\s*\)\s*\{(?:[^{}]|\{[^}]*\})*return\s+location\.origin\s*\+\s*["\']([^"\']+)["\']', re.DOTALL)
        for match in pattern3.finditer(code):
            method_name = match.group(1)
            suffix = match.group(2)
            # Store as a pattern that needs base URL resolution
            self.methods[method_name] = f"ORIGIN{suffix}"
            self.methods[f"this.{method_name}"] = f"ORIGIN{suffix}"
        
        # Pattern 4: Environment object support - Extract common config patterns
        pattern4 = re.compile(r'(?:apiUrl|baseUrl|serverUrl|apiEndpoint)\s*:\s*["\']([^"\']+)["\']', re.IGNORECASE)
        for match in pattern4.finditer(code):
            url = match.group(1)
            if self._is_url_like(url):
                # Store with a recognizable key
                self.methods['environmentApiUrl'] = url
    
    def _extract_service_properties(self, code, filename, file_vars):
        """Extract service property patterns like this.propertyName=this.methodCall()+'/path'"""
        # Pattern: this.propertyName = this.methodCall() + "/path"
        pattern = re.compile(r'this\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*this\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(\s*\)\s*\+\s*["\']([^"\']+)["\']')
        
        for match in pattern.finditer(code):
            property_name = match.group(1)
            method_name = match.group(2)
            path_suffix = match.group(3)
            
            # Try to resolve the method
            method_result = self._resolve_method(method_name)
            
            if method_result:
                # Combine method result with suffix
                full_endpoint = method_result + path_suffix
                
                # Register as a service property
                self.service_properties[property_name] = {
                    'endpoint': full_endpoint,
                    'method_call': f"this.{method_name}()",
                    'suffix': path_suffix,
                    'source': filename
                }
                
                # Also register as a regular variable
                self._register_variable(property_name, full_endpoint, filename, file_vars, 95)
                self._register_variable(f"this.{property_name}", full_endpoint, filename, file_vars, 98)
    
    def _resolve_method(self, method_name):
        """Resolve a method call to its return value"""
        # Check direct method name
        if method_name in self.methods:
            return self.methods[method_name]
        
        # Check with this. prefix
        if f"this.{method_name}" in self.methods:
            return self.methods[f"this.{method_name}"]
        
        # Common method names that return API base URLs
        common_methods = {
            'getRootUrl': '/api',
            'getBaseUrl': '/api',
            'getApiUrl': '/api',
            'getServerUrl': '/api',
            'getApiBaseUrl': '/api'
        }
        
        if method_name in common_methods:
            return f"ORIGIN{common_methods[method_name]}"
        
        return None
    
    def _extract_obfuscated_strings(self, code, filename):
        """Extract string arrays used in obfuscated code"""
        pattern = re.compile(r'function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(\s*\)\s*\{[^}]*const\s+\w+\s*=\s*\[([^\]]+)\]', re.DOTALL)
        
        for match in pattern.finditer(code):
            func_name = match.group(1)
            array_content = match.group(2)
            
            string_pattern = r'["\']([^"\']+)["\']'
            strings = re.findall(string_pattern, array_content)
            
            for idx, string in enumerate(strings):
                if self._is_url_like(string) and not self._is_noise_value(string):
                    key = f"{func_name}_{idx}"
                    self.obfuscated_strings[key] = string
    
    def _is_noise_value(self, value):
        """Check if value is noise"""
        v = value.lower()
        
        for keyword in NOISE_KEYWORDS:
            if keyword in v:
                return True
        
        if len(value) < 2:
            return True
        
        return False
    
    def _register_variable(self, var_name, var_value, filename, file_vars, confidence):
        """Register a variable with confidence scoring"""
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
        
        if self._could_be_base_url(var_value):
            self.potential_bases[var_name] = var_value
        
        if self._is_base_url(var_value):
            self.global_scope[var_name] = var_value
    
    def _is_url_like(self, value):
        """Check if value looks like a URL or endpoint"""
        if len(value) < 2:
            return False
        return (
            value.startswith('http') or 
            value.startswith('/') or
            value.startswith('#/') or
            value.startswith('ORIGIN') or
            any(term in value.lower() for term in ['api', 'endpoint', 'service', 'rest', 'graphql', 
                                                    'fetch', 'data', 'dashboard', 'master', 'project'])
        )
    
    def _could_be_base_url(self, value):
        """Check if this could potentially be a base URL"""
        if len(value) < 3:
            return False
        
        if not (value.startswith('http') or value.startswith('/') or value.startswith('#/') or value.startswith('ORIGIN')):
            return False
        
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
        
        if not (value.startswith('http') or value.startswith('/') or value.startswith('#/') or value.startswith('ORIGIN')):
            return False
        
        patterns = [
            r'^https?://[^/]+',
            r'^/',
            r'^#/',
            r'^ORIGIN',
        ]
        
        return any(re.search(p, value) for p in patterns)
    
    def resolve(self, var_name):
        """Resolve a variable name to its value"""
        if var_name in self.variables:
            return self.variables[var_name]['value']
        
        if var_name in self.property_accesses:
            return self.property_accesses[var_name]
        
        if var_name in self.service_properties:
            return self.service_properties[var_name]['endpoint']
        
        return None
    
    def resolve_with_fallback(self, var_name):
        """Resolve variable with multiple fallback strategies"""
        if var_name in self.global_scope:
            return self.global_scope[var_name]
        if var_name in self.potential_bases:
            return self.potential_bases[var_name]
        if var_name in self.variables:
            return self.variables[var_name]['value']
        if var_name in self.property_accesses:
            return self.property_accesses[var_name]
        if var_name in self.service_properties:
            return self.service_properties[var_name]['endpoint']
        
        if f"this.{var_name}" in self.variables:
            return self.variables[f"this.{var_name}"]['value']
        
        for prop in ['url', 'serverURL', 'baseURL', 'apiURL', 'rootUrl', 'baseUrl']:
            if var_name == prop and prop in self.property_accesses:
                return self.property_accesses[prop]
        
        return None
    
    def resolve_method_call(self, method_call_str):
        """Resolve a method call like 'this.getRootUrl()' to its return value"""
        method_call_str = method_call_str.strip()
        
        if method_call_str.endswith('()'):
            method_call_str = method_call_str[:-2]
        
        if method_call_str in self.methods:
            return self.methods[method_call_str]
        
        if method_call_str.startswith('this.'):
            method_name = method_call_str[5:]
            if method_name in self.methods:
                return self.methods[method_name]
        else:
            if f"this.{method_call_str}" in self.methods:
                return self.methods[f"this.{method_call_str}"]
        
        return None
    
    def get_all_base_urls(self):
        """Get all potential base URLs found"""
        return {**self.global_scope, **self.potential_bases, **self.property_accesses}
    
    def get_all_service_properties(self):
        """Get all service properties found"""
        return self.service_properties

# ==============================================================================
# CLASS: ENHANCED RPC PATTERN EXTRACTOR WITH METHOD CALL SUPPORT
# ==============================================================================
class EnhancedRPCExtractor:
    """Extracts RPC-style endpoint definitions with method call support"""
    
    def __init__(self, resolver):
        self.resolver = resolver
        self.endpoints = []
    
    def extract_rpc_patterns(self, code, filename):
        """Extract RPC concatenation patterns including method calls"""
        found = []
        
        # Pattern: this.property = this.method() + "path"
        pattern_method = re.compile(r'this\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*this\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(\s*\)\s*\+\s*["\']([^"\']+)["\']')
        for match in pattern_method.finditer(code):
            property_name = match.group(1)
            method_name = match.group(2)
            suffix = match.group(3)
            
            if self._is_noise(method_name, suffix):
                continue
            
            base_url = self.resolver.resolve_method_call(f"this.{method_name}")
            
            if base_url:
                full_endpoint = base_url + suffix
                if self._is_valid_endpoint(full_endpoint):
                    method = self._guess_method_from_key(property_name)
                    
                    found.append({
                        'endpoint': full_endpoint,
                        'method': method,
                        'pattern': f'this.{property_name} = this.{method_name}() + "{suffix}"',
                        'key': property_name,
                        'type': 'RPC_METHOD_CALL',
                        'source': filename,
                        'classification': 'RPC_ENDPOINT',
                        'confidence': 98
                    })
        
        # Pattern 1: Object property with concatenation (key: var + "endpoint")
        pattern1 = re.compile(r'(\w+)\s*:\s*([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*\+\s*["\']([^"\']+)["\']')
        for match in pattern1.finditer(code):
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
        pattern2 = re.compile(r'(?:var|let|const)?\s*(\w+)\s*=\s*([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*\+\s*["\']([^"\']+)["\']')
        for match in pattern2.finditer(code):
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
        pattern3 = re.compile(r'`\$\{([a-zA-Z_$][a-zA-Z0-9_$.]*)\}([^`]+)`')
        for match in pattern3.finditer(code):
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
        pattern4 = re.compile(r'(?:get|post|put|delete|patch|fetch|postDataFromUrl|getDataFromUrl|postDataFromUrlWithoutSerialize|getDataFromUrlAndSendData|getRawDataFromUrl)\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*\+\s*["\']([^"\']+)["\']', re.IGNORECASE)
        for match in pattern4.finditer(code):
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
        pattern5 = re.compile(r'([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*\+\s*["\']([^"\']+)["\']\s*\+\s*["\']([^"\']+)["\']')
        for match in pattern5.finditer(code):
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
        pattern6 = re.compile(r'return\s+([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*\+\s*["\']([^"\']+)["\']')
        for match in pattern6.finditer(code):
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
        pattern7 = re.compile(r'[\[{,]\s*([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*\+\s*["\']([^"\']+)["\']')
        for match in pattern7.finditer(code):
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
        """Validate if endpoint looks legitimate - AGGRESSIVE FILTERING"""
        if not endpoint or len(endpoint) < 3:
            return False
        
        # CRITICAL FIX 1: Reject endpoints with spaces (URLs shouldn't have spaces unless encoded)
        if ' ' in endpoint:
            return False
        
        # CRITICAL FIX 2: Reject template literal syntax that wasn't resolved
        if '${' in endpoint or '{{' in endpoint or '`' in endpoint:
            return False
        
        # CRITICAL FIX 3: Reject unbalanced parenthesis/brackets (indicates parsing error)
        try:
            if endpoint.count('(') != endpoint.count(')'):
                return False
            if endpoint.count('[') != endpoint.count(']'):
                return False
            if endpoint.count('{') != endpoint.count('}'):
                return False
        except:
            return False
        
        # CRITICAL FIX 4: Reject URLs with "undefined" or "null" literals
        if 'undefined' in endpoint.lower() or '/null' in endpoint or '/null/' in endpoint:
            return False
        
        # Check standard noise patterns
        for pattern in NOISE_PATTERNS:
            if re.search(pattern, endpoint, re.IGNORECASE):
                return False
        
        endpoint_lower = endpoint.lower()
        
        # Check against noise keywords
        for keyword in NOISE_KEYWORDS:
            if keyword in endpoint_lower:
                return False
        
        # CRITICAL FIX 5: Reject Excel/internal framework paths
        if '/xl/' in endpoint_lower or 'worksheet' in endpoint_lower:
            return False
        
        # CRITICAL FIX 6: Reject Angular internal files
        if any(x in endpoint_lower for x in ['ngdirectivedef', 'ngpipedef', 'ngmoduledef', 'nginjectabledef', 'nginjectordef']):
            return False
        
        # Normalize ORIGIN placeholder
        if endpoint.startswith('ORIGIN'):
            endpoint = endpoint.replace('ORIGIN', '/')
        
        # Must start with valid protocol or path
        if not (endpoint.startswith('http') or endpoint.startswith('/') or endpoint.startswith('#/')):
            return False
        
        # Validation for http URLs
        if endpoint.startswith('http'):
            try:
                parsed = urllib.parse.urlparse(endpoint)
                if not parsed.netloc:
                    return False
                # CRITICAL FIX 7: Reject if path is empty or just slash (too generic)
                if not parsed.path or parsed.path == '/':
                    return False
                # CRITICAL FIX 8: Reject paths that are clearly not APIs (single letter paths)
                path_parts = [p for p in parsed.path.split('/') if p]
                if len(path_parts) == 1 and len(path_parts[0]) <= 2:
                    return False
            except:
                return False
        
        # CRITICAL FIX 9: Must contain typical URL separators or patterns
        valid_indicators = ['/', '.json', '.xml', '?', '=', 'api', 'get', 'post', 'update', 'delete', 'fetch']
        if not any(x in endpoint_lower for x in valid_indicators):
            return False
        
        # CRITICAL FIX 10: Reject if it looks like a file extension that's not an API
        if endpoint_lower.endswith(('.js', '.css', '.png', '.jpg', '.svg', '.woff', '.ttf', '.eot')):
            return False
        
        # CRITICAL FIX 11: Reject malformed query strings
        if '?' in endpoint:
            query_part = endpoint.split('?')[1] if len(endpoint.split('?')) > 1 else ''
            # If query exists but is just special chars, reject
            if query_part and not any(c.isalnum() for c in query_part):
                return False
        
        return True
    
    def _is_noise(self, var_name, suffix):
        """Check if this is noise pattern - ULTRA STRICT"""
        combined = (var_name + suffix).lower()
        
        # CRITICAL: Check all noise keywords
        for keyword in NOISE_KEYWORDS:
            if keyword in combined:
                return True
        
        # CRITICAL: Reject if suffix is too short (likely error)
        if len(suffix) < 2:
            return True
        
        # CRITICAL: Reject if suffix is just special chars or spaces
        if suffix.strip() in [':', '/', '?', '=', ',', '.', '-', '_']:
            return True
        
        # CRITICAL: Reject error message patterns
        if any(x in combined for x in ['caused by', 'valid digit', 'error', ' dis', ' jaj', ' jar', ' lup', ' rep', ' tup']):
            return True
        
        # CRITICAL: Reject template syntax
        if any(x in suffix for x in ['${', '{{', '`', '\\n', '\\r']):
            return True
        
        # CRITICAL: Reject CSS/style fragments
        if any(x in suffix for x in ['animation-timing', 'sheet ${', 'sheet,', 'sheet[', 'sheet(', 'sheet.']):
            return True
        
        # CRITICAL: Reject single letter suffixes (like ' x', ' a')
        if suffix.strip() and len(suffix.strip()) == 1:
            return True
        
        # CRITICAL: Reject CSS units
        if suffix.strip() in ['px', 'ms', 'em', 'rem', 'vh', 'vw', 'pt', '%']:
            return True
        
        # CRITICAL: Reject if it's clearly a constant name, not a path
        if suffix.strip().isupper() and '_' in suffix:  # Like ON_PROPERTY
            return True
        
        return False
    
    def _guess_method_from_key(self, key):
        """Guess HTTP method from property key name"""
        k = key.lower()
        if any(x in k for x in ['get', 'fetch', 'load', 'search', 'query', 'find', 'read', 'list', 'show', 'all']):
            return 'GET'
        elif any(x in k for x in ['post', 'create', 'add', 'insert', 'new', 'submit', 'send', 'save', 'upload']):
            return 'POST'
        elif any(x in k for x in ['put', 'update', 'modify', 'edit', 'change']):
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
        self.resolver = EnhancedVariableResolver()
        self.rpc_extractor = EnhancedRPCExtractor(self.resolver)
        self.analyzed_js_files = set()  # Track analyzed files to avoid duplicates

    def scan(self, js_urls, json_urls):
        print(f"\n[PHASE 2] Enhanced Analysis with Method Call Resolution")
        print(f"  Processing: {len(js_urls)} JS files, {len(json_urls)} JSON configs")
        
        # STEP 1: Extract ALL variables and methods
        print(f"\n  [Step 1/4] Extracting variables and methods...")
        js_contents = {}
        
        for i, url in enumerate(js_urls, 1):
            if i % 10 == 0:
                print(f"    Progress: [{i}/{len(js_urls)}]", end='\r')
            
            if any(x in url.lower() for x in LOW_VALUE_JS):
                continue
                
            try:
                r = self.session.get(url, timeout=10, verify=False)
                if r.status_code == 200:
                    filename = url.split('/')[-1]
                    js_contents[url] = r.text
                    self.resolver.extract_all_variables(r.text, filename)
                    self.analyzed_js_files.add(url)
            except requests.exceptions.Timeout:
                pass  # Skip files that timeout
            except Exception as e:
                pass  # Skip files with errors
        
        print(f"\n    [+] Extracted {len(self.resolver.variables)} unique variables")
        print(f"    [+] Found {len(self.resolver.methods)} method definitions")
        print(f"    [+] Found {len(self.resolver.service_properties)} service properties")
        print(f"    [+] Found {len(self.resolver.get_all_base_urls())} potential base URLs")
        
        # Show discovered methods
        if self.resolver.methods:
            print(f"\n  [Discovered Methods]")
            for method, value in list(self.resolver.methods.items())[:10]:
                print(f"    {method}() = {value}")
        
        # Show discovered service properties
        if self.resolver.service_properties:
            print(f"\n  [Discovered Service Properties]")
            for prop, data in list(self.resolver.service_properties.items())[:20]:
                print(f"    this.{prop} = {data['method_call']} + \"{data['suffix']}\"")
                print(f"      → {data['endpoint']}")
        
        # STEP 2: Extract RPC patterns
        print(f"\n  [Step 2/4] Extracting RPC patterns with method calls...")
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

        print(f"    [+] Found {rpc_count} RPC-style endpoints")
        
        # STEP 3: Extract service property endpoints
        print(f"\n  [Step 3/4] Extracting service property endpoints...")
        service_count = 0
        
        for prop_name, prop_data in self.resolver.service_properties.items():
            full_url = self.normalizer.normalize(prop_data['endpoint'])
            method = self._guess_method_from_key(prop_name)
            
            self.add_endpoint(
                full_url,
                method,
                [],
                'SERVICE_PROPERTY',
                prop_data['source'],
                'BACKEND_API',
                97
            )
            service_count += 1
        
        print(f"    [+] Found {service_count} service property endpoints")
        
        # STEP 4: Standard analysis
        print(f"\n  [Step 4/4] Standard endpoint analysis...")
        
        for json_url in json_urls:
            self.analyze_json_config(json_url)
        
        for url, code in js_contents.items():
            self.analyze_code(code, url)
        
        print(f"\n  [+] Total endpoints discovered: {len(self.endpoints)}")
        
        return self.endpoints

    def analyze_json_config(self, json_url):
        """Extract ALL string values from JSON config files"""
        try:
            r = self.session.get(json_url, timeout=10, verify=False)
            if r.status_code != 200:
                return
            
            data = r.json()
            filename = json_url.split('/')[-1]
            
            self._extract_from_json(data, filename, json_url)
            
        except json.JSONDecodeError:
            pass  # Not valid JSON
        except requests.exceptions.Timeout:
            pass  # Timeout
        except Exception:
            pass  # Other errors

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
        """Determine if a JSON string value is an endpoint"""
        v = value.lower()
        k = key.lower()
        
        for keyword in NOISE_KEYWORDS:
            if keyword in v:
                return "NOISE"
        
        if any(re.search(p, value) for p in NOISE_PATTERNS):
            return "NOISE"
        
        if any(re.search(p, value, re.IGNORECASE) for p in API_INDICATORS):
            return "BACKEND_API"
        
        api_key_indicators = ['api', 'endpoint', 'url', 'service', 'path', 'route', 'dashboard']
        if any(ind in k for ind in api_key_indicators):
            if value.startswith('/') or value.startswith('http') or value.startswith('#/'):
                return "BACKEND_API"
        
        if value.startswith('http'):
            if not any(d in v for d in IGNORED_DOMAINS):
                return "EXTERNAL_API"
        
        if (value.startswith('/') or value.startswith('#/')) and len(value) > 3:
            if '/' in value[1:] or '#' in value:
                return "FRONTEND_ROUTE"
        
        return "NOISE"

    def _guess_method_from_key(self, key):
        """Guess HTTP method from key name"""
        k = key.lower()
        if any(x in k for x in ['get', 'fetch', 'load', 'search', 'query', 'find', 'read', 'list', 'show', 'view', 'all', 'dash']):
            return 'GET'
        elif any(x in k for x in ['post', 'create', 'add', 'insert', 'new', 'submit', 'send', 'save', 'upload']):
            return 'POST'
        elif any(x in k for x in ['put', 'update', 'modify', 'edit', 'change']):
            return 'PUT'
        elif any(x in k for x in ['delete', 'remove', 'destroy', 'drop']):
            return 'DELETE'
        return 'GET'

    def analyze_code(self, code, source):
        """Analyze JavaScript code for endpoints"""
        if any(x in source.lower() for x in LOW_VALUE_JS):
            return

        # HTTP patterns
        for m in re.finditer(r'this\.http\.(get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]+)', code, re.IGNORECASE):
            full_url = self.normalizer.normalize(m.group(2))
            self.process(full_url, m.group(1).upper(), m.start(), code, source, "HTTP_THIS", "BACKEND_API", 95)
        
        for m in re.finditer(r'\.http\.(get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]+)', code, re.IGNORECASE):
            full_url = self.normalizer.normalize(m.group(2))
            self.process(full_url, m.group(1).upper(), m.start(), code, source, "HTTP", "BACKEND_API", 90)
        
        for m in re.finditer(r'this\.httpclient\.(get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]+)', code, re.IGNORECASE):
            full_url = self.normalizer.normalize(m.group(2))
            self.process(full_url, m.group(1).upper(), m.start(), code, source, "HTTPCLIENT_THIS", "BACKEND_API", 95)
        
        for m in re.finditer(r'\.httpclient\.(get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]+)', code, re.IGNORECASE):
            full_url = self.normalizer.normalize(m.group(2))
            self.process(full_url, m.group(1).upper(), m.start(), code, source, "HTTPCLIENT", "BACKEND_API", 90)
        
        # Router patterns
        for m in re.finditer(r'this\.router\.navigate(?:ByUrl)?\s*\(\s*[\'"`]([^\'"`]+)', code, re.IGNORECASE):
            full_url = self.normalizer.normalize(m.group(1))
            self.process(full_url, "GET", m.start(), code, source, "ROUTER_NAV_THIS", "FRONTEND_ROUTE", 85)
        
        for m in re.finditer(r'this\.route\.navigate(?:ByUrl)?\s*\(\s*[\'"`]([^\'"`]+)', code, re.IGNORECASE):
            full_url = self.normalizer.normalize(m.group(1))
            self.process(full_url, "GET", m.start(), code, source, "ROUTE_NAV_THIS", "FRONTEND_ROUTE", 85)
        
        for m in re.finditer(r'router\.navigate(?:ByUrl)?\s*\(\s*[\'"`]([^\'"`]+)', code, re.IGNORECASE):
            full_url = self.normalizer.normalize(m.group(1))
            self.process(full_url, "GET", m.start(), code, source, "ROUTER_NAV", "FRONTEND_ROUTE", 80)
        
        for m in re.finditer(r'route\.navigate(?:ByUrl)?\s*\(\s*[\'"`]([^\'"`]+)', code, re.IGNORECASE):
            full_url = self.normalizer.normalize(m.group(1))
            self.process(full_url, "GET", m.start(), code, source, "ROUTE_NAV", "FRONTEND_ROUTE", 80)
        
        for m in re.finditer(r'window\.open\s*\(\s*[\'"]([^\'"]+)[\'"]', code, re.IGNORECASE):
            full_url = self.normalizer.normalize(m.group(1))
            self.process(full_url, "GET", m.start(), code, source, "WINDOW_OPEN", "OPEN_REDIRECT_SINK", 90)
        
        # Fetch API
        for m in re.finditer(r'fetch\s*\(\s*[\'"`]([^\'"`]+)', code, re.IGNORECASE):
            full_url = self.normalizer.normalize(m.group(1))
            method = self.detect_method(code, m.start())
            self.process(full_url, method, m.start(), code, source, "FETCH_API", "BACKEND_API", 85)
        
        # Location patterns
        for m in re.finditer(r'location\.origin\s*\+\s*["\']([^"\']+)["\']', code, re.IGNORECASE):
            path = m.group(1)
            clean_path = self._extract_clean_route(path)
            if clean_path:
                full_url = self.normalizer.normalize(clean_path)
                self.process(full_url, "GET", m.start(), code, source, "LOCATION_ORIGIN", "FRONTEND_ROUTE", 85)
        
        # Hash routes
        for pattern in HASH_ROUTE_PATTERNS:
            for m in re.finditer(pattern, code):
                route = m.group(1)
                if self._is_valid_route(route):
                    full_url = self.normalizer.normalize(route)
                    self.process(full_url, "GET", m.start(), code, source, "HASH_ROUTE", "FRONTEND_ROUTE", 75)
        
        for m in re.finditer(r'window\.open\s*\(\s*location\.origin\s*\+\s*["\']([^"\']+)["\']', code, re.IGNORECASE):
            path = m.group(1)
            clean_path = self._extract_clean_route(path)
            if clean_path:
                full_url = self.normalizer.normalize(clean_path)
                self.process(full_url, "GET", m.start(), code, source, "WINDOW_OPEN_ROUTE", "FRONTEND_ROUTE", 88)
        
        # String literals with API patterns
        for m in re.finditer(r'["\']([/#][^\'"]{3,100}?)["\']', code):
            url = m.group(1)
            if self.has_api_pattern(url):
                cls = self.classify(url)
                if cls != "NOISE":
                    full_url = self.normalizer.normalize(url)
                    self.process(full_url, self.detect_method(code, m.start()), m.start(), code, source, "STATIC_CODE", cls, 50)

    def analyze_code_from_dynamic(self, code, source):
        """
        Special method for analyzing code discovered during dynamic phase.
        This is called from the feedback loop.
        """
        filename = source.split('/')[-1] if '/' in source else source
        
        # Extract variables and methods from this new code
        self.resolver.extract_all_variables(code, filename)
        
        # Extract RPC patterns
        rpc_endpoints = self.rpc_extractor.extract_rpc_patterns(code, filename)
        for ep in rpc_endpoints:
            full_url = self.normalizer.normalize(ep['endpoint'])
            self.add_endpoint(
                full_url, 
                ep['method'], 
                [], 
                ep['type'] + '_DYNAMIC', 
                ep['source'], 
                ep['classification'], 
                ep['confidence']
            )
        
        # Run standard code analysis
        self.analyze_code(code, source)

    def _extract_clean_route(self, path):
        """Extract clean route from JavaScript concatenation"""
        path = path.strip()
        
        if '+' in path:
            path = path.split('+')[0]
        
        if '(' in path and ')' in path:
            parts = re.split(r'[()]', path)
            for part in parts:
                if '#/' in part:
                    path = part
                    break
        
        path = path.strip('"\'')
        
        if self._is_valid_route(path):
            return path
        return None
    
    def _is_valid_route(self, route):
        """Check if route is valid"""
        if not route:
            return False
        
        route_lower = route.lower()
        
        for keyword in NOISE_KEYWORDS:
            if keyword in route_lower:
                return False
        
        return ('#/' in route or route.startswith('/') or route.startswith('#/'))

    def process(self, url, method, pos, code, source, type, classification, confidence):
        if self.is_valid(url):
            params = self.extract_params(code, pos + len(url))
            self.add_endpoint(url, method, params, type, source, classification, confidence)

    def add_endpoint(self, url, method, params, type, source, classification, confidence):
        url = self._clean_url(url)
        
        if not url:
            return
        
        # CRITICAL FIX: Normalize trailing slashes for deduplication
        # /api/users and /api/users/ should be treated as the same
        url_normalized = url.rstrip('/')
        
        url_lower = url_normalized.lower()
        for keyword in NOISE_KEYWORDS:
            if keyword in url_lower:
                return
        
        if any(re.search(p, url_normalized) for p in NOISE_PATTERNS):
            return
        
        # ADDITIONAL FIX: Reject if URL path is too short (likely noise)
        try:
            parsed = urllib.parse.urlparse(url_normalized)
            if parsed.path and len(parsed.path.strip('/')) < 2:
                return  # Paths like /x or /a are noise
        except:
            pass
        
        # Check for duplicates using normalized URL
        for e in self.endpoints:
            # Normalize existing endpoint for comparison
            existing_url = e['endpoint'].rstrip('/')
            if existing_url == url_normalized and e['method'] == method:
                e['parameters'] = list(set(e['parameters'] + params))
                if confidence > self.confidence_scores.get(f"{method}:{url_normalized}", 0):
                    e['type'] = type
                    e['classification'] = classification
                    self.confidence_scores[f"{method}:{url_normalized}"] = confidence
                return
        
        self.endpoints.append({
            "endpoint": url,  # Use original URL (with or without trailing slash as originally found)
            "method": method, 
            "parameters": params, 
            "type": type, 
            "source": source if isinstance(source, str) else source.split('/')[-1][:80],
            "classification": classification
        })
        self.confidence_scores[f"{method}:{url_normalized}"] = confidence
    
    def _clean_url(self, url):
        """Clean malformed URLs"""
        url = str(url).strip()
        
        if url.startswith('ORIGIN'):
            url = url.replace('ORIGIN', '')
        
        if url.startswith('https://') and 'window.open' in url:
            match = re.search(r'location\.origin\s*\+\s*["\']([^"\']+)["\']', url)
            if match:
                path = match.group(1)
                clean_path = self._extract_clean_route(path)
                if clean_path:
                    return self.normalizer.normalize(clean_path)
            return None
        
        url = url.replace('\"', '')
        
        if '(' in url and ')' in url and ('window.open' in url or 'location.origin' in url):
            match = re.search(r'["\']([^"\']+)["\']', url)
            if match:
                url = match.group(1)
        
        if ')' in url:
            url = url.split(')')[0]
        if ',' in url and '_self' in url:
            url = url.split(',')[0]
        
        return url

    def is_valid(self, url):
        """Validate URL - ULTRA STRICT"""
        if not url:
            return False
            
        url = url.strip()
        if len(url) < 3 or ' ' in url: 
            return False
        
        url_lower = url.lower()
        
        # CRITICAL: Check noise keywords first
        for keyword in NOISE_KEYWORDS:
            if keyword in url_lower:
                return False
        
        # CRITICAL: Check strict blocks
        if any(b in url.lower() for b in STRICT_BLOCKS): 
            return False
        
        # CRITICAL: Check noise patterns
        for p in FALSE_POSITIVE_PATTERNS:
            if re.search(p, url, re.IGNORECASE): 
                return False
        
        # CRITICAL: Additional specific checks from real scan
        # Block single letter paths like /x, /a
        if re.search(r'/[a-zA-Z]$', url):
            return False
        
        # Block CSS unit paths like /px, /ms
        if re.search(r'/(?:px|ms|em|rem|vh|vw|pt)$', url):
            return False
        
        # Block unresolved template syntax
        if any(x in url for x in ['${', '{{', '`', '\\n']):
            return False
        
        # Block URLs with "undefined" or "null" in path
        if '/undefined/' in url or '/null/' in url or url.endswith('/undefined') or url.endswith('/null'):
            return False
        
        # Block framework internal files
        if url.endswith('.js') and any(x in url_lower for x in ['ngdirectivedef', 'ngpipedef', 'ngmoduledef', 'nginjectabledef', 'nginjectordef']):
            return False
        
        # Block template.html
        if 'template.html' in url_lower:
            return False
        
        # Block Excel internal paths
        if '/xl/' in url_lower or 'worksheet' in url_lower:
            return False
        
        # Block error message fragments
        if any(x in url_lower for x in ['caused by:', 'valid digit', 'animation-timing-function']):
            return False
        
        # Block ON_PROPERTY and other leaked constants
        if 'ON_PROPERTY' in url or 'ON_INIT' in url:
            return False
        
        if url.startswith('#/'):
            return True
        
        # Block non-API file extensions
        if url.lower().endswith(('.js', '.css', '.png', '.svg', '.woff', '.jpg', '.jpeg', '.gif', '.ico', '.ttf', '.eot', '.woff2')):
            return False
        
        return True

    def has_api_pattern(self, url):
        """Check for API patterns"""
        return any(re.search(p, url, re.IGNORECASE) for p in API_INDICATORS)

    def classify(self, url):
        """Classify endpoint type"""
        u = url.lower()
        if self.has_api_pattern(url): 
            return "BACKEND_API"
        if any(x in u for x in ['/login', '/dashboard', '/profile', '/#/', '/admin']): 
            return "FRONTEND_ROUTE"
        if u.startswith('#/'):
            return "FRONTEND_ROUTE"
        if u.startswith('http'): 
            return "EXTERNAL_API" if not any(d in u for d in IGNORED_DOMAINS) else "NOISE"
        if (u.startswith('/') or u.startswith('#/')) and len(u) > 3:
            return "FRONTEND_ROUTE"
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
        self.base_path = parsed.path.rstrip('/')
    
    def normalize(self, endpoint):
        """Convert endpoint to complete URL"""
        if endpoint.startswith('http://') or endpoint.startswith('https://'):
            return endpoint
        
        if endpoint.startswith('//'):
            return f'{self.scheme}:{endpoint}'
        
        if endpoint.startswith('/'):
            if '#/' in endpoint:
                return f'{self.scheme}://{self.netloc}{endpoint}'
            return f'{self.scheme}://{self.netloc}{endpoint}'
        
        if endpoint.startswith('#/'):
            return f'{self.scheme}://{self.netloc}{self.base_path}{endpoint}'
        
        if '#/' in endpoint:
            if endpoint.startswith('/'):
                return f'{self.scheme}://{self.netloc}{endpoint}'
            else:
                return f'{self.scheme}://{self.netloc}/{endpoint}'
        
        return f'{self.scheme}://{self.netloc}/{endpoint}'

# ==============================================================================
# FEDERATION HUNTER - ENHANCED WITH RECURSIVE DISCOVERY
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

        print(f"  Deep scanning JavaScript files...")
        processed_files = set()
        scan_errors = 0
        
        while self.scan_queue:
            url = self.scan_queue.popleft()
            if url in processed_files: 
                continue
            processed_files.add(url)
            
            if any(x in url.lower() for x in LOW_VALUE_JS): 
                continue

            try:
                r = self.session.get(url, timeout=10, verify=False)
                if r.status_code == 200:
                    self.hunt_webpack_chunks(r.text, url)
                    self.hunt_config_references(r.text, url)
                elif r.status_code == 403:
                    print(f"\n  [!] 403 Forbidden on {url.split('/')[-1]} - Site may be blocking scraper")
                    scan_errors += 1
            except requests.exceptions.Timeout:
                scan_errors += 1
            except Exception as e:
                if scan_errors < 3:  # Only show first few errors
                    print(f"\n  [!] Error fetching {url.split('/')[-1]}: {type(e).__name__}")
                scan_errors += 1
        
        if scan_errors > 0:
            print(f"  [!] {scan_errors} files failed to download")

        print(f"  [+] JS: {len(self.found_js_files)}, JSON: {len(self.found_json_files)}")
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
                r = self.session.get(url, timeout=8, verify=False)
                if r.status_code == 200:
                    try:
                        r.json()
                        self.found_json_files.add(url)
                        print(f"  [*] Found config: {path}")
                    except json.JSONDecodeError:
                        pass  # Not valid JSON
            except requests.exceptions.Timeout:
                pass  # Config file doesn't exist, timeout is expected
            except Exception as e:
                # Only print unexpected errors
                if "404" not in str(e) and "Connection" not in str(e):
                    print(f"  [!] Error checking {path}: {e}")

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
                    r = self.session.get(full_url, timeout=5, verify=False)
                    if r.status_code == 200:
                        try:
                            r.json()
                            self.found_json_files.add(full_url)
                        except json.JSONDecodeError:
                            pass
                except requests.exceptions.Timeout:
                    pass
                except Exception:
                    pass

    def crawl_html(self):
        """Crawl HTML for script tags"""
        print(f"  [*] Fetching HTML from {self.target_url}...")
        try:
            # Add verify=False to handle self-signed certs
            r = self.session.get(self.target_url, timeout=15, verify=False)
            print(f"  [*] Status Code: {r.status_code}")
            
            if r.status_code != 200:
                print(f"  [!] Non-200 status code. Content length: {len(r.text)}")
                # Still try to parse even with non-200 status
            
            soup = BeautifulSoup(r.text, 'html.parser')
            scripts = soup.find_all('script', src=True)
            print(f"  [*] Found {len(scripts)} script tags in HTML")
            
            if len(scripts) == 0:
                print(f"  [!] WARNING: No <script> tags found. This might be a dynamic SPA.")
                print(f"  [!] HTML preview (first 500 chars):")
                print(f"      {r.text[:500]}")
            
            for s in scripts:
                url = urllib.parse.urljoin(self.target_url, s['src'])
                if not any(b in url for b in IGNORED_DOMAINS):
                    if url not in self.found_js_files:
                        self.found_js_files.add(url)
                        self.scan_queue.append(url)
                        
        except requests.exceptions.SSLError as e:
            print(f"  [!] SSL Error: {e}")
            print(f"  [!] Try adding verify=False or check SSL certificate")
        except requests.exceptions.ConnectionError as e:
            print(f"  [!] Connection Error: {e}")
            print(f"  [!] Cannot reach target. Check internet connection.")
        except Exception as e:
            print(f"  [!] CRITICAL ERROR in crawl_html: {type(e).__name__}: {e}")

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
# DYNAMIC INTERCEPTOR - ENHANCED WITH FEEDBACK LOOP
# ==============================================================================
class DynamicInterceptor:
    """
    Enhanced Dynamic Interceptor with recursive feedback loop.
    
    Key improvements:
    1. Captures lazy-loaded JS files and feeds them back to static analyzer
    2. Multi-pass navigation with increasing depth
    3. Better handling of authentication redirects
    4. Intelligent route prioritization
    """
    
    def __init__(self, target_url, analyzer, cookies=None, max_routes=25, max_depth=3):
        self.target_url = target_url
        self.analyzer = analyzer  # Feedback loop to static analyzer
        self.domain = urllib.parse.urlparse(target_url).netloc
        self.base_url = f"{urllib.parse.urlparse(target_url).scheme}://{urllib.parse.urlparse(target_url).netloc}"
        self.cookies = cookies
        self.endpoints = []
        self.seen_requests = set()
        self.analyzed_js_files = set()  # Track JS files we've already analyzed
        self.discovered_routes = set()
        self.max_routes = max_routes
        self.max_depth = max_depth
        self.session_storage_data = {}
        self.local_storage_data = {}

    def run(self, static_endpoints=[]):
        if not PLAYWRIGHT_AVAILABLE: 
            print(f"\n[PHASE 3] Playwright not available - skipping")
            return []
            
        print(f"\n[PHASE 3] Dynamic Discovery with Recursive Feedback Loop")
        print(f"  Max routes per depth: {self.max_routes}, Max depth: {self.max_depth}")
        
        # Multi-pass navigation with increasing depth
        for depth in range(1, self.max_depth + 1):
            print(f"\n  [Depth {depth}/{self.max_depth}] Navigating routes...")
            
            # Get routes for this depth level
            routes = self._get_routes_for_depth(static_endpoints, depth)
            
            if not routes:
                print(f"    No new routes at depth {depth}")
                break
            
            print(f"    Routes to visit: {len(routes)}")
            
            # Navigate with feedback loop
            self._navigate_routes_with_feedback(routes, depth)
            
            print(f"    Analyzed {len(self.analyzed_js_files)} JS files so far")
            print(f"    Discovered {len(self.discovered_routes)} unique routes")
            print(f"    Captured {len(self.endpoints)} API calls")
        
        print(f"\n  [+] Total dynamic endpoints: {len(self.endpoints)}")
        print(f"  [+] Total JS files analyzed: {len(self.analyzed_js_files)}")
        
        return self.endpoints

    def _get_routes_for_depth(self, static_endpoints, depth):
        """Get routes to visit at a specific depth level"""
        routes = []
        
        if depth == 1:
            # First pass: start with target URL
            routes = [self.target_url]
            
            # Add high-priority frontend routes
            for e in static_endpoints:
                if e['classification'] == 'FRONTEND_ROUTE':
                    clean = self._clean_route(e['endpoint'])
                    if clean and clean not in routes:
                        routes.append(clean)
        else:
            # Subsequent passes: use newly discovered routes
            routes = list(self.discovered_routes)
            
            # Also check for any new routes from the analyzer
            for e in self.analyzer.endpoints:
                if e['classification'] == 'FRONTEND_ROUTE':
                    clean = self._clean_route(e['endpoint'])
                    if clean and clean not in self.discovered_routes:
                        routes.append(clean)
        
        # Prioritize routes with hash fragments and deeper paths
        routes = self._prioritize_routes(routes, depth)
        
        # Limit routes per depth
        return routes[:self.max_routes]

    def _clean_route(self, endpoint):
        """Clean and normalize a route for navigation - WITH AGGRESSIVE FILTERING"""
        if not endpoint:
            return None
        
        # Remove quotes and whitespace
        clean = endpoint.replace('"', '').replace("'", "").strip()
        
        # CRITICAL FIX 1: Reject routes containing 'undefined' or 'null' string literals
        if 'undefined' in clean.lower() or '/null' in clean or '/null/' in clean:
            return None
        
        # CRITICAL FIX 2: Reject routes with template syntax
        if '${' in clean or '{{' in clean or '`' in clean:
            return None
        
        # CRITICAL FIX 3: Reject routes with spaces (malformed)
        if ' ' in clean:
            return None
        
        # CRITICAL FIX 4: Reject internal framework files
        if any(x in clean.lower() for x in ['ngdirectivedef', 'ngpipedef', 'ngmoduledef', 'template.html', '/xl/']):
            return None
        
        # Build full URL
        if clean.startswith('http'):
            full = clean
        elif clean.startswith('/'):
            full = urllib.parse.urljoin(self.base_url, clean)
        else:
            return None
        
        # Only return if it's from our domain
        if self.domain in full:
            return full
        
        return None

    def _prioritize_routes(self, routes, depth):
        """Prioritize routes based on depth and characteristics"""
        def route_score(route):
            score = 0
            
            # Prefer hash routes at all depths
            if '#/' in route:
                score += 100
            
            # Prefer deeper paths
            path_depth = route.count('/')
            score += path_depth * 10
            
            # Prefer routes with meaningful names (not just IDs)
            if any(keyword in route.lower() for keyword in ['dashboard', 'admin', 'user', 'profile', 'settings', 'manage', 'list', 'view', 'edit']):
                score += 50
            
            # Penalize routes that look like they need parameters
            if re.search(r'/\d+$', route) or re.search(r'/:[\w]+', route):
                score -= 30
            
            return score
        
        return sorted(routes, key=route_score, reverse=True)

    def _navigate_routes_with_feedback(self, routes, depth):
        """Navigate routes and feed discovered JS back to analyzer"""
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                ignore_https_errors=True,
                viewport={'width': 1920, 'height': 1080}
            )
            
            # Set cookies
            if self.cookies:
                context.add_cookies([
                    {"name": k, "value": v, "domain": self.domain, "path": "/"} 
                    for k, v in self.cookies.items()
                ])
            
            page = context.new_page()
            
            # Subscribe to response events for feedback loop
            page.on("response", self._handle_response)
            
            # Navigate each route
            for i, route in enumerate(routes, 1):
                print(f"      [{i}/{len(routes)}] {route[:80]}", end='\r')
                
                try:
                    # Navigate and wait for network to settle
                    response = page.goto(route, wait_until="networkidle", timeout=20000)
                    
                    # Check if we got redirected to login
                    if response and 'login' in page.url.lower() and 'login' not in route.lower():
                        print(f"\n      [!] Redirected to login, skipping further routes at this depth")
                        break
                    
                    # Extract any newly discovered routes from the page
                    self._extract_routes_from_page(page)
                    
                    # Small delay to let any async requests complete
                    time.sleep(0.5)
                    
                    # Try to extract storage data (for state preservation)
                    self._extract_storage_data(page)
                    
                except Exception as e:
                    # Don't let one failure stop the whole scan
                    continue
            
            print()  # New line after progress
            browser.close()

    def _extract_routes_from_page(self, page):
        """Extract route references from the current page"""
        try:
            # Extract from href attributes
            links = page.query_selector_all('a[href]')
            for link in links[:50]:  # Limit to prevent hanging
                try:
                    href = link.get_attribute('href')
                    if href:
                        clean = self._clean_route(href)
                        if clean and clean not in self.discovered_routes:
                            self.discovered_routes.add(clean)
                except:
                    pass
            
            # Extract from router-link or similar SPA navigation
            spa_links = page.query_selector_all('[routerlink], [ui-sref], [ng-href], [to]')
            for link in spa_links[:50]:
                try:
                    for attr in ['routerlink', 'ui-sref', 'ng-href', 'to']:
                        value = link.get_attribute(attr)
                        if value:
                            clean = self._clean_route(value)
                            if clean and clean not in self.discovered_routes:
                                self.discovered_routes.add(clean)
                except:
                    pass
                    
        except:
            pass

    def _extract_storage_data(self, page):
        """Extract localStorage and sessionStorage for state preservation"""
        try:
            # This could be used to maintain auth state across navigations
            local_storage = page.evaluate('() => { return JSON.stringify(localStorage); }')
            session_storage = page.evaluate('() => { return JSON.stringify(sessionStorage); }')
            
            if local_storage:
                self.local_storage_data = json.loads(local_storage)
            if session_storage:
                self.session_storage_data = json.loads(session_storage)
        except:
            pass

    def _handle_response(self, response):
        """
        Handle all responses - the core of the feedback loop.
        
        This captures:
        1. New JavaScript files → feeds back to static analyzer
        2. API calls → adds to endpoints list
        3. Route references → adds to discovered routes
        """
        url = response.url
        
        # Skip ignored domains
        if any(b in url for b in IGNORED_DOMAINS):
            return
        
        # Skip if already seen
        if url in self.seen_requests:
            return
        
        self.seen_requests.add(url)
        
        try:
            content_type = response.headers.get("content-type", "").lower()
            
            # 1. FEEDBACK LOOP: Capture and analyze new JavaScript files
            if url.endswith('.js') or "javascript" in content_type:
                if url not in self.analyzer.analyzed_js_files:
                    self.analyzer.analyzed_js_files.add(url)
                    self.analyzed_js_files.add(url)
                    
                    try:
                        # Download JS content
                        code = response.text()
                        
                        if len(code) > 100:  # Ignore empty files
                            # CRITICAL: Feed back to static analyzer
                            self.analyzer.analyze_code_from_dynamic(code, url)
                    except:
                        pass
            
            # 2. Capture API calls (JSON responses)
            elif "application/json" in content_type:
                try:
                    endpoint = url.split('?')[0]
                    
                    # Try to infer HTTP method from request
                    method = "GET"  # Default assumption for responses
                    
                    # Extract parameters from query string
                    params = []
                    parsed = urllib.parse.urlparse(url)
                    if parsed.query:
                        params.extend(urllib.parse.parse_qs(parsed.query).keys())
                    
                    self.endpoints.append({
                        "endpoint": endpoint,
                        "method": method,
                        "parameters": list(set(params)),
                        "type": "DYNAMIC_API_CALL",
                        "source": "Browser",
                        "classification": "VERIFIED_API"
                    })
                except:
                    pass
            
            # 3. Extract route references from HTML responses
            elif "text/html" in content_type:
                try:
                    html = response.text()
                    
                    # Extract hash routes from HTML
                    hash_routes = re.findall(r'href=["\']([^"\']*#/[^"\']+)["\']', html)
                    for route in hash_routes:
                        clean = self._clean_route(route)
                        if clean and clean not in self.discovered_routes:
                            self.discovered_routes.add(clean)
                except:
                    pass
                    
        except:
            pass

# ==============================================================================
# REPORT GENERATION & EXCEL CONVERSION
# ==============================================================================
def json_to_excel(input_file, output_file):
    """Converts JSON report to Excel format"""
    if not PANDAS_AVAILABLE:
        print("\n[!] Pandas not installed. Skipping Excel conversion.")
        return

    current_dir = os.getcwd()
    input_path = os.path.join(current_dir, input_file)
    output_path = os.path.join(current_dir, output_file)

    print(f"\n[PHASE 5] Excel Conversion")
    print(f"  Work Dir: {current_dir}")
    
    if not os.path.exists(input_path):
        print(f"  [X] ERROR: Input file '{input_file}' not found.")
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
                "Type": item.get('type', ''),
                "Classification": item.get('classification', '')
            })
            
        df = pd.DataFrame(rows)
        
        with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='API_Endpoints')
            worksheet = writer.sheets['API_Endpoints']
            for column in df:
                col_idx = df.columns.get_loc(column) + 1
                worksheet.column_dimensions[chr(64 + col_idx)].width = 25 
        
        print(f"  [+] SUCCESS! Created: {output_file}")
        
    except Exception as e:
        print(f"  [X] ERROR Converting to Excel: {str(e)}")

def save_report(static, dynamic, filename="results.json"):
    print(f"\n[PHASE 4] Generating Report")
    
    combined = {}
    for item in static + dynamic:
        key = f"{item['method']}:{item['endpoint']}"
        if key not in combined: 
            combined[key] = item
        else:
            combined[key]['parameters'] = list(set(combined[key]['parameters'] + item['parameters']))
            # Dynamic endpoints take precedence
            if item['type'].startswith('DYNAMIC'):
                combined[key]['type'] = item['type']
                combined[key]['classification'] = 'VERIFIED_API'

    # Filter out noise
    pre_filter_count = len(combined)
    results = []
    
    for item in combined.values():
        # Skip noise classification
        if item['classification'] == "NOISE":
            continue
        
        endpoint = item['endpoint']
        endpoint_lower = endpoint.lower()
        
        # FINAL QUALITY GATE: Ultra-strict filtering
        is_garbage = False
        
        # Check 1: Contains template syntax
        if any(x in endpoint for x in ['${', '{{', '`', '\\n', '\\r']):
            is_garbage = True
        
        # Check 2: Contains spaces (except in query params)
        if ' ' in endpoint.split('?')[0]:  # Check path only, not query string
            is_garbage = True
        
        # Check 3: Single letter paths
        if re.search(r'/[a-zA-Z]$', endpoint):
            is_garbage = True
        
        # Check 4: CSS units
        if re.search(r'/(?:px|ms|em|rem|vh|vw|pt)$', endpoint):
            is_garbage = True
        
        # Check 5: Framework internals
        if any(x in endpoint_lower for x in ['ngdirectivedef', 'ngpipedef', 'ngmoduledef', 'nginjectabledef', 'nginjectordef', 'template.html']):
            is_garbage = True
        
        # Check 6: Excel paths
        if '/xl/' in endpoint_lower or 'worksheet' in endpoint_lower:
            is_garbage = True
        
        # Check 7: Error messages
        if any(x in endpoint_lower for x in ['caused by:', 'valid digit', 'animation-timing']):
            is_garbage = True
        
        # Check 8: Ends with colon (malformed)
        if endpoint.rstrip('/').endswith(':'):
            is_garbage = True
        
        # Check 9: undefined/null in path
        if '/undefined' in endpoint or '/null/' in endpoint:
            is_garbage = True
        
        # Check 10: ON_PROPERTY and constants
        if 'ON_PROPERTY' in endpoint or 'ON_INIT' in endpoint:
            is_garbage = True
        
        # Check 11: Too short paths (likely fragments)
        try:
            parsed = urllib.parse.urlparse(endpoint)
            path_parts = [p for p in parsed.path.split('/') if p and p not in ['api', 'api_rc_permit', 'api_isolation', 'api_lessonlearnt', 'api_rc_usermanage', 'api_gasmeasure']]
            if len(path_parts) == 0:  # Only base path like /api_isolation/
                # Allow if it's explicitly a base API path
                if not endpoint.rstrip('/').endswith(('_permit', '_isolation', '_lessonlearnt', '_usermanage', '_gasmeasure', '_rc_permittwo')):
                    if item['classification'] != 'VERIFIED_API':  # Don't filter verified APIs
                        is_garbage = True
        except:
            pass
        
        # Check 12: Vimeo/Vzaar (external, not relevant unless user wants)
        if 'vimeo.com' in endpoint_lower or 'vzaar.com' in endpoint_lower:
            is_garbage = True
        
        if not is_garbage:
            results.append(item)
    
    filtered_count = pre_filter_count - len(results)
    if filtered_count > 0:
        print(f"  [*] Filtered out {filtered_count} garbage endpoints")
    
    results.sort(key=lambda x: (
        {
            "VERIFIED_API": 0,
            "RPC_METHOD_CALL": 1,
            "SERVICE_PROPERTY": 2,
            "RPC_ENDPOINT": 3,
            "BACKEND_API": 4, 
            "JSON_CONFIG": 5,
            "OPEN_REDIRECT_SINK": 6,
            "FRONTEND_ROUTE": 7,
            "EXTERNAL_API": 8
        }.get(x['classification'], 9), 
        x['endpoint']
    ))

    # Count different types
    rpc_method_endpoints = [e for e in results if 'RPC_METHOD_CALL' in e.get('type', '')]
    service_endpoints = [e for e in results if 'SERVICE_PROPERTY' in e.get('type', '')]
    rpc_endpoints = [e for e in results if e['classification'] == 'RPC_ENDPOINT']
    dynamic_discovered = [e for e in results if 'DYNAMIC' in e.get('type', '')]
    
    report = {
        "scan_metadata": {
            "scanner": "Advanced Endpoint Scanner - Enhanced Edition",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_endpoints": len(results)
        },
        "summary": {
            "verified_runtime": len([x for x in results if x['classification'] == "VERIFIED_API"]),
            "dynamic_discovered": len(dynamic_discovered),
            "rpc_method_calls": len(rpc_method_endpoints),
            "service_properties": len(service_endpoints),
            "rpc_patterns": len(rpc_endpoints),
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
    print(f"SCAN COMPLETE")
    print(f"{'='*70}")
    print(f"  Total Endpoints:            {len(results)}")
    print(f"  [*] Verified Runtime APIs:  {report['summary']['verified_runtime']}")
    print(f"  [*] Dynamic Discovered:     {report['summary']['dynamic_discovered']}")
    print(f"  [*] RPC Method Calls:       {report['summary']['rpc_method_calls']}")
    print(f"  [*] Service Properties:     {report['summary']['service_properties']}")
    print(f"  [*] RPC Patterns:           {report['summary']['rpc_patterns']}")
    print(f"  Backend APIs:               {report['summary']['backend']}")
    print(f"  JSON Configs:               {report['summary']['json_config']}")
    print(f"  Frontend Routes:            {report['summary']['frontend']}")
    print(f"  Open Redirect Sinks:        {report['summary']['sinks']}")
    
    print(f"\n[FILE] JSON saved: {filename}")
    
    json_to_excel(filename, 'results.xlsx')

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Advanced Endpoint Scanner - Enhanced Edition',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  python scanner.py --target https://example.com
  
  # Scan with cookies
  python scanner.py --target https://example.com
  
  # Deep scan with more routes and depth
  python scanner.py --target https://example.com --max-routes 50 --max-depth 5
  
  # Quick scan (fewer routes, less depth)
  python scanner.py --target https://example.com --max-routes 10 --max-depth 2 --no-cookies
        """
    )
    
    parser.add_argument('--target', type=str, help='Target URL')
    parser.add_argument('--no-cookies', action='store_true', help='Skip cookie input')
    parser.add_argument('--output', type=str, default='results.json', help='Output file path')
    parser.add_argument('--max-routes', type=int, default=25, help='Max routes to visit per depth (default: 25)')
    parser.add_argument('--max-depth', type=int, default=3, help='Max navigation depth (default: 3)')
    parser.add_argument('--quiet', action='store_true', help='Suppress progress output')
    
    return parser.parse_args()

# ==============================================================================
# MAIN (WITH COMPREHENSIVE ERROR HANDLING)
# ==============================================================================
if __name__ == "__main__":
    print("=" * 70)
    print("ADVANCED ENDPOINT SCANNER - ENHANCED EDITION")
    print("Recursive lazy-loading discovery for modern SPAs")
    print("=" * 70 + "\n")
    
    try:
        # Parse command-line arguments
        args = parse_args()
        
        # Get target URL
        if args.target:
            target = args.target
            print(f"Target: {target}")
        else:
            target = input("Target URL: ").strip()
            if not target:
                print("[X] No URL provided")
                sys.exit(1)
        
        if not target.startswith("http"):
            target = "https://" + target
        
        # DEBUG: Test connection BEFORE starting scan
        print(f"\n[DEBUG] Testing connection to {target}...")
        try:
            test_resp = requests.get(target, timeout=10, verify=False)
            print(f"[DEBUG] ✓ Connection successful (Status: {test_resp.status_code})")
            if test_resp.status_code == 403:
                print(f"[!] WARNING: Got 403 Forbidden. Site may block python-requests.")
                print(f"[!] Consider using different User-Agent or checking for WAF/Cloudflare.")
        except requests.exceptions.SSLError as e:
            print(f"[!] SSL Error: {e}")
            print(f"[!] Continuing with verify=False...")
        except requests.exceptions.ConnectionError as e:
            print(f"[X] FATAL: Cannot connect to target: {e}")
            print(f"[X] Check your internet connection or if the site is down.")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Connection test error: {e}")
            print(f"[!] Attempting to continue anyway...")
        
        # Handle cookies
        cookies = {}
        if not args.no_cookies:
            cookie_choice = input("\nAdd cookies? (y/n): ").strip().lower()
            if cookie_choice == 'y':
                print("Enter cookies (press Enter with empty name to finish):")
                while True:
                    name = input("  Cookie name: ").strip()
                    if not name:
                        break
                    value = input("  Cookie value: ").strip()
                    cookies[name] = value
        
        # Setup session with realistic User-Agent
        session = requests.Session()
        session.cookies.update(cookies)
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        start_time = time.time()
        
        print("\n" + "="*70)
        print("STARTING ENHANCED SCAN")
        print("="*70)
        
        # Phase 1: Discovery
        hunter = EnhancedFederationHunter(session, target)
        js_files, json_files = hunter.run()
        
        # DEBUG CHECK: Warn if no JS files found
        if len(js_files) == 0:
            print("\n" + "!"*70)
            print("WARNING: No JavaScript files were found in Phase 1!")
            print("!"*70)
            print("\nPossible causes:")
            print("  1. The site is a pure SPA that renders <script> tags dynamically")
            print("  2. The site blocked the scraper (WAF/Cloudflare/403)")
            print("  3. The URL points to a directory listing, not an HTML page")
            print("  4. The site requires authentication cookies")
            
            if PLAYWRIGHT_AVAILABLE:
                print("\n[*] Playwright is available - continuing to Phase 3 for dynamic discovery")
            else:
                print("\n[!] Playwright not installed. Install it for better SPA support:")
                print("    pip install playwright")
                print("    python -m playwright install chromium")
            
            print("\nContinuing scan with limited data...\n")
        
        # Phase 2: Static Analysis
        analyzer = EnhancedStaticAnalyzer(session, target)
        static_endpoints = analyzer.scan(js_files, json_files)
        
        if len(static_endpoints) == 0 and len(js_files) > 0:
            print("\n[!] WARNING: Found JS files but extracted 0 endpoints")
            print("[!] The JavaScript might be heavily obfuscated or use dynamic imports")
        
        # Phase 3: Dynamic Interception with Feedback Loop
        interceptor = DynamicInterceptor(
            target, 
            analyzer,  # Pass analyzer for feedback loop
            cookies,
            max_routes=args.max_routes,
            max_depth=args.max_depth
        )
        dynamic_endpoints = interceptor.run(static_endpoints)
        
        # Add any endpoints discovered during dynamic phase back to static
        static_endpoints.extend(analyzer.endpoints)
        
        elapsed = time.time() - start_time
        print(f"\n[TIME] Total scan time: {elapsed:.1f}s")
        
        # Phase 4 & 5: Save results
        output_file = args.output if hasattr(args, 'output') else 'results.json'
        save_report(static_endpoints, dynamic_endpoints, output_file)
        
        # Print absolute path to results
        abs_path = os.path.abspath(output_file)
        print(f"\n[RESULTS] Saved to: {abs_path}")
        
        # Final summary
        total = len(set([f"{e['method']}:{e['endpoint']}" for e in static_endpoints + dynamic_endpoints]))
        if total == 0:
            print("\n" + "="*70)
            print("NO ENDPOINTS FOUND - TROUBLESHOOTING")
            print("="*70)
            print("\nThe scan completed but found 0 endpoints. This usually means:")
            print("  1. The target blocks automated scrapers (check for 403 errors above)")
            print("  2. The site is a pure SPA with no initial JavaScript in HTML")
            print("  3. All endpoints are dynamically loaded and Playwright is not installed")
            print("\nSolutions:")
            print("  • Add authentication cookies if the site requires login")
            print("  • Install Playwright: pip install playwright && python -m playwright install chromium")
            print("  • Try a different target URL (e.g., a specific page instead of root)")
            print("  • Check if the site has a WAF/Cloudflare protection")
        
    except KeyboardInterrupt:
        print("\n\n[X] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n[X] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)