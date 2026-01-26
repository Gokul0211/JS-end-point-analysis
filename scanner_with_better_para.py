#!/usr/bin/env python3
"""
Advanced Endpoint Scanner - Enhanced Edition
Extracts API endpoints, routes, and service configurations from JavaScript applications
with recursive lazy-loading discovery and advanced SPA support

Final Integration:
- Ultimate Parameter Extraction (Body, Query, Header, Path, Nested)
- Dynamic Body Parameter Interception & Merging
- Robust Framework Noise Filtering (Tuned for Business Logic)
- Recursive Swagger/OpenAPI Parsing
- ScopeManager: Infinite-range parameter lookup & variable tracing
- TypeScript Interface Parsing
- Strict Static Query String Extraction
- NEW: HttpParams .set() detection & Single-letter variable support
- FIXED: Missing _enhance_array_harvested_endpoints method
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

# EXTENDED NOISE FILTER (UI/CSS/Framework terms)
# REMOVED common params to ensure valid data is captured
NOISE_KEYWORDS = [
    'helvetica', 'arial', 'courier', 'times', 'verdana',
    '__html2canvas__', '_pseudoelement_',
    'klmnopqrstuvwxyz',
    'expressionchangedafterithasbeenchecked',
    'caused by:', 'valid digit info', 'ngdirectivedef', 
    'ngpipedef', 'ngmoduledef', 'nginjectabledef', 'nginjectordef',
    'node_modules', 'sourcemap',
    'animation-timing-function', 'sheet ${', 'sheet,', 'sheet[',
    ' dis', ' jaj', ' jar', ' lup', ' rep', ' tup',
    'on_property', 'template.html',
    # UI/CSS Noise
    'padding', 'margin', 'width', 'height', 'color', 'background', 'border',
    'font', 'display', 'align', 'justify', 'style', 'encapsulation',
    'buttontext', 'ok', 'cancel', 'inputfieldrequired'
]

BASE_URL_BLACKLIST = [
    r'w3\.org', r'xmlns', r'2000/svg', r'1999/xhtml',
    r'ExpressionChangedAfterItHasBeenCheckedError',
    r'klmnopqrstuvwxyz',
]

STRICT_BLOCKS = [
    'webpack', '__webpack', 'sourcemap',
    'ngdirectivedef', 'ngpipedef', 'ngmoduledef', 
    'nginjectabledef', 'nginjectordef',
    'template.html',
    '/xl/worksheets/',
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
    r'^http:-', r'^http:/[^/]', r'^https?:px', r'^https?://[^/]*$',
    r'\$\{', r'\{\{', r'undefined', r'\bnull\b',
    r'/xl/worksheets/', r'\s', r'\(\$', r'\?\$',
    r'caused by:', r'valid digit info', r'animation-timing-function',
    r'/[a-z]$', r'(?:^|/)(?:px|ms|em|rem|vh|vw)$',
    r'\?id=\$\{', r':\$\{', r'\(!', r'\[\w+\]$',
    r'/sheet\s', r'sheet\$', r'sheet,', r'sheet\[', r'sheet\(',
    r'//\s*$', r':\\n', r'\}\\n',
]

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
# CLASS: ULTIMATE PARAMETER EXTRACTOR
# ==============================================================================
class UltimateParameterExtractor:
    """
    Extracts ALL parameter types with type inference and enum detection.
    Handles: Query strings, headers, nested objects, destructuring, enums.
    """
    
    def __init__(self):
        self.framework_noise = {
            'providedIn', 'factory', 'token', 'deps', 'useFactory', 'useClass',
            'useValue', 'multi', 'inject', 'optional', 'self', 'skipSelf',
            'selector', 'template', 'templateUrl', 'styleUrls', 'styles',
            'encapsulation', 'changeDetection', 'animations', 'host',
            'providers', 'viewProviders', 'moduleId', 'interpolation',
            'ngOnInit', 'ngOnDestroy', 'ngOnChanges', 'ngDoCheck',
            'ngAfterContentInit', 'ngAfterContentChecked', 'ngAfterViewInit',
            'ngAfterViewChecked',
            'validators', 'asyncValidators', 'updateOn', 'valid', 'invalid',
            'pristine', 'dirty', 'touched', 'untouched', 'valueChanges',
            'path', 'component', 'redirectTo', 'pathMatch', 'children',
            'loadChildren', 'canActivate', 'canDeactivate', 'resolve',
            'observe', 'responseType', 'reportProgress', 'withCredentials',
            'headers', 'params', 'context',
            'width', 'height', 'margin', 'padding', 'border', 'color',
            'background', 'font', 'display', 'position', 'top', 'left',
            'right', 'bottom', 'flex', 'grid',
            'useState', 'useEffect', 'useContext', 'useReducer', 'useCallback',
            'useMemo', 'useRef', 'useImperativeHandle', 'useLayoutEffect',
            'key', 'ref', 'children', 'defaultProps', 'displayName',
            'timeout', 'retries', 'baseURL', 'transformRequest', 'transformResponse',
            'paramsSerializer', 'adapter', 'auth', 'xsrfCookieName', 'xsrfHeaderName',
            '__proto__', 'constructor', 'prototype', 'hasOwnProperty',
            'isPrototypeOf', 'propertyIsEnumerable', 'toLocaleString',
            'toString', 'valueOf',
            'options', 'config', 'settings', 'meta',
            'buttonText', 'InputFieldRequired'
        }
        
        self.noise_keywords = {'this', 'self', 'super', 'window', 'document', 'undefined', 'null', 'true', 'false'}
    
    def extract_all_params(self, code, endpoint_url, position):
        result = {'body': [], 'query': [], 'headers': [], 'path': []}
        start = max(0, position - 500)
        end = min(len(code), position + 500)
        context = code[start:end]
        
        result['body'] = self._enhance_with_types(self._extract_body_params(context, code, position), context)
        result['query'] = self._enhance_with_types(self._extract_query_params(context, endpoint_url), context)
        result['headers'] = self._enhance_with_types(self._extract_header_params(context), context)
        result['path'] = self._extract_path_params(endpoint_url, context)
        
        return self._filter_all_noise(result)
    
    def extract_typescript_interfaces(self, code):
        """Extract parameter names from TypeScript interfaces."""
        params = []
        interface_pattern = r'interface\s+(\w+(?:Request|Payload|Body|Params|Query|Data))\s*\{([^}]+)\}'
        for match in re.finditer(interface_pattern, code):
            interface_body = match.group(2)
            property_pattern = r'(\w+)\??:\s*[\w\[\]<>,\s]+'
            for prop_match in re.finditer(property_pattern, interface_body):
                prop_name = prop_match.group(1)
                # Allow 1 char params for minified code
                if len(prop_name) < 1: continue 
                if prop_name in self.framework_noise: continue
                if self._is_likely_noise(prop_name): continue
                params.append(prop_name)
        return list(set(params))

    def filter_list(self, params):
        clean = []
        for p in params:
            if p not in self.framework_noise and p not in self.noise_keywords and not self._is_likely_noise(p):
                clean.append(p)
        return clean

    def _extract_body_params(self, context, full_code, position):
        params = []
        var_pattern = r'\.(?:post|put|patch)\s*\([^,]+,\s*(\w+)'
        match = re.search(var_pattern, context)
        if match:
            params.extend(self._trace_variable_definition(full_code, match.group(1), position))
        
        inline_pattern = r'\.(?:post|put|patch)\s*\([^,]+,\s*\{([^}]+)\}'
        match = re.search(inline_pattern, context)
        if match:
            obj_content = match.group(1)
            params.extend(re.findall(r'\b(\w+)\s*(?:,|\})', obj_content))
            params.extend(re.findall(r'["\']?(\w+)["\']?\s*:', obj_content))
            params.extend(re.findall(r'\[\s*["\']?(\w+)["\']?\s*\]:', obj_content))
            for spread_var in re.findall(r'\.\.\.\s*(\w+)', obj_content):
                params.extend(self._trace_variable_definition(full_code, spread_var, position))
        
        match = re.search(r'body\s*:\s*(\w+)', context)
        if match:
            params.extend(self._trace_variable_definition(full_code, match.group(1), position))
        
        match = re.search(r'(?:options|config)\.body\s*=\s*(\w+)', context)
        if match:
            params.extend(self._trace_variable_definition(full_code, match.group(1), position))

        match = re.search(r'\{\s*body\s*:\s*(\w+)', context)
        if match:
            params.extend(self._trace_variable_definition(full_code, match.group(1), position))

        return list(set(params))
    
    def _extract_query_params(self, context, endpoint_url):
        params = []
        # Pattern for url + "?id=" + id
        params.extend(re.findall(r'[?&](\w+)=', context))
        
        match = re.search(r'params\s*:\s*\{([^}]+)\}', context)
        if match:
            params.extend(re.findall(r'["\']?(\w+)["\']?\s*:', match.group(1)))
        
        match = re.search(r'new\s+URLSearchParams\s*\(\s*\{([^}]+)\}', context)
        if match:
            params.extend(re.findall(r'["\']?(\w+)["\']?\s*:', match.group(1)))
        
        match = re.search(r'`[^`]*\?([^`]+)`', context)
        if match:
            params.extend(re.findall(r'(\w+)=', match.group(1)))
        
        match = re.search(r'params\s*:\s*\{([^}]+)\}', context)
        if match:
            params.extend(re.findall(r'["\']?(\w+)["\']?\s*:', match.group(1)))
        
        if '?' in endpoint_url:
            try:
                parsed = urllib.parse.urlparse(endpoint_url)
                params.extend(urllib.parse.parse_qs(parsed.query).keys())
            except: pass
        
        return list(set(params))
    
    def _extract_header_params(self, context):
        params = []
        match = re.search(r'headers\s*:\s*\{([^}]+)\}', context)
        if match:
            header_names = re.findall(r'["\']([A-Za-z-]+)["\']:\s*\w+', match.group(1))
            params.extend([h for h in header_names if h.startswith('X-') or h in ['Authorization', 'Auth-Token']])
        params.extend(re.findall(r'setRequestHeader\s*\(\s*["\']([^"\']+)["\']', context))
        return list(set(params))
    
    def _extract_path_params(self, endpoint_url, context):
        params = []
        for i, match in enumerate(re.finditer(r'\{(\w+)\}', endpoint_url), 1):
            params.append({'name': match.group(1), 'type': 'string', 'position': i})
        
        matches = re.findall(r'["\']\/["\'].*?\+.*?(\w+)', context)
        for match in matches:
            if match not in [p['name'] for p in params]:
                params.append({'name': match, 'type': 'string', 'position': len(params) + 1})
        return params
    
    def _trace_variable_definition(self, code, var_name, search_pos):
        search_area = code[:search_pos]
        patterns = [rf'(?:let|const|var)\s+{re.escape(var_name)}\s*=\s*\{{', rf'\b{re.escape(var_name)}\s*=\s*\{{']
        match = None
        for pattern in patterns:
            matches = list(re.finditer(pattern, search_area))
            if matches:
                match = matches[-1]
                break
        
        if not match: return []
        content = self._extract_balanced_braces(code[match.end() - 1:])
        if not content: return []
        
        params = []
        params.extend(re.findall(r'["\']?(\w+)["\']?\s*:', content))
        params.extend(re.findall(r'\{\s*(\w+)\s*(?:,|\})', content))
        params.extend(re.findall(r'\[\s*["\']?(\w+)["\']?\s*\]:', content))
        
        for nested_match in re.finditer(r'(\w+)\s*:\s*\{', content):
            parent = nested_match.group(1)
            nested = self._extract_balanced_braces(content[nested_match.end() - 1:])
            if nested:
                params.extend([f"{parent}.{k}" for k in re.findall(r'["\']?(\w+)["\']?\s*:', nested)])
        
        return list(set([p for p in params if len(p) >= 1]))
    
    def _extract_balanced_braces(self, code_from_brace):
        if not code_from_brace or code_from_brace[0] != '{': return ""
        balance = 0
        content = ""
        in_string = False
        escape_next = False
        string_char = None
        for char in code_from_brace:
            if escape_next:
                escape_next = False
                content += char
                continue
            if char == '\\':
                escape_next = True
                content += char
                continue
            if char in ['"', "'", '`']:
                if not in_string:
                    in_string = True
                    string_char = char
                elif char == string_char:
                    in_string = False
                    string_char = None
                content += char
                continue
            if not in_string:
                if char == '{': balance += 1
                elif char == '}': balance -= 1
                content += char
                if balance == 0: break
        return content[1:-1] if balance == 0 else ""
    
    def _enhance_with_types(self, params, context):
        enhanced = []
        for param in params:
            enhanced.append({
                'name': param,
                'type': self._infer_type(param, context),
                'enum': self._extract_enum_values(param, context),
                'required': bool(re.search(rf'if\s*\(\s*!{re.escape(param)}\s*\)', context))
            })
        return enhanced
    
    def _infer_type(self, param, context):
        patterns = [
            (r'\b' + re.escape(param) + r'\s*[:=]\s*(\d+)', 'integer'),
            (r'\b' + re.escape(param) + r'\s*[:=]\s*(true|false)', 'boolean'),
            (r'\b' + re.escape(param) + r'\s*[:=]\s*\[', 'array'),
            (r'\b' + re.escape(param) + r'\s*[:=]\s*\{', 'object'),
        ]
        for pattern, type_name in patterns:
            if re.search(pattern, context): return type_name
        return 'string'
    
    def _extract_enum_values(self, param, context):
        enum_values = []
        match = re.search(rf'switch\s*\(\s*{re.escape(param)}\s*\)\s*\{{([^}}]+)\}}', context)
        if match: enum_values.extend(re.findall(r'case\s+["\'](\w+)["\']:', match.group(1)))
        enum_values.extend(re.findall(rf'{re.escape(param)}\s*===\s*["\'](\w+)["\']', context))
        match = re.search(rf'\[["\'](\w+)["\'](?:,\s*["\'](\w+)["\'])*\]\.includes\s*\(\s*{re.escape(param)}', context)
        if match: enum_values.extend(re.findall(r'["\'](\w+)["\']', match.group(0)))
        return list(set(enum_values)) if enum_values else None

    def _is_likely_noise(self, param):
        p = param.lower()
        if len(param) <= 1: return False # FIXED: Allow single chars (e.g. e, t, n)
        if any(p.endswith(unit) for unit in ['px', 'em', 'rem', 'pt', 'vh', 'vw']): return True
        if param.startswith(('ng', 'rx', '$', '_')): return True
        if param.isupper() and len(param) > 2: return True
        if p.startswith(('on', 'handle')) or p.endswith(('handler', 'listener', 'callback')): return True
        return False

    def _filter_all_noise(self, result):
        for category in ['body', 'query', 'headers', 'path']:
            if isinstance(result[category], list):
                result[category] = [p for p in result[category] if (isinstance(p, dict) and p['name'] not in self.framework_noise and not self._is_likely_noise(p['name'])) or (isinstance(p, str) and p not in self.framework_noise and not self._is_likely_noise(p))]
        return result

# ==============================================================================
# CLASS: SCOPE MANAGER
# ==============================================================================
class ScopeManager:
    """
    Parses entire JavaScript files to map functions, classes, and variables.
    Solves the "800 char limit" by creating a global lookup table.
    """
    def __init__(self):
        self.scopes = []  # List of {start, end, params, type, name}
        self.variable_map = {}  # var_name -> {value, definition_pos, scope}
        self.class_scopes = []  # Track class boundaries
        self.imports = {}  # Track imports for cross-file resolution
        self.array_objects = {}  # Track array contents with metadata
        
    def parse_file(self, code, filename="unknown"):
        """Main entry point - parses all structures in a file"""
        self.scopes = []
        self.variable_map = {}
        self.class_scopes = []
        self.imports = {}
        self.array_objects = {}
        
        try:
            self._map_imports(code)
            self._map_classes(code)
            self._map_functions(code)
            self._map_variables(code)
            self._map_array_objects(code)
        except Exception as e:
            # Silently continue on parse errors to avoid breaking the scan
            pass
        
        return True

    def _map_imports(self, code):
        """Track import statements for cross-file variable resolution"""
        import_pattern = re.compile(r'import\s+\{([^}]+)\}\s+from\s+["\']([^"\']+)["\']')
        for match in import_pattern.finditer(code):
            imports_str = match.group(1)
            module = match.group(2)
            imported_names = [n.strip() for n in imports_str.split(',')]
            for name in imported_names:
                self.imports[name] = {'module': module, 'pos': match.start()}

    def _map_classes(self, code):
        """Map class boundaries (Angular components, React classes)"""
        class_pattern = re.compile(r'(?:export\s+)?class\s+(\w+)(?:\s+extends\s+\w+)?\s*\{')
        
        for match in class_pattern.finditer(code):
            class_name = match.group(1)
            start = match.start()
            end = self._find_closing_brace(code, match.end() - 1)
            
            if end != -1:
                self.class_scopes.append({
                    'name': class_name,
                    'start': start,
                    'end': end,
                    'type': 'class'
                })

    def _map_functions(self, code):
        """Finds all functions and their parameter lists"""
        patterns = [
            # Standard function: function name(params) {
            r'function\s+(\w+)\s*\(([^)]*)\)\s*\{',
            # Arrow function assigned: const name = (params) => {
            r'(?:const|let|var)\s+(\w+)\s*=\s*\(([^)]*)\)\s*=>\s*\{',
            # Method in object/class: name(params) {
            r'(\w+)\s*\(([^)]*)\)\s*\{',
            # Arrow function in object: name: (params) => {
            r'(\w+)\s*:\s*\(([^)]*)\)\s*=>\s*\{',
        ]
        
        for pattern in patterns:
            func_pattern = re.compile(pattern)
            for match in func_pattern.finditer(code):
                try:
                    func_name = match.group(1) if match.group(1) else "anonymous"
                    args_str = match.group(2) if len(match.groups()) > 1 else ""
                    
                    start = match.start()
                    brace_pos = code.find('{', match.start())
                    if brace_pos == -1:
                        continue
                        
                    end = self._find_closing_brace(code, brace_pos)
                    
                    if end != -1:
                        params = self._parse_function_params(args_str)
                        
                        self.scopes.append({
                            'name': func_name,
                            'start': start,
                            'end': end,
                            'params': params,
                            'type': 'function'
                        })
                except Exception:
                    continue

    def _parse_function_params(self, args_str):
        """Enhanced parameter parsing with destructuring support"""
        if not args_str.strip():
            return []
            
        params = []
        current = ""
        depth = 0
        
        for char in args_str + ",":
            if char in '{[(':
                depth += 1
                current += char
            elif char in '}])':
                depth -= 1
                current += char
            elif char == ',' and depth == 0:
                if current.strip():
                    params.extend(self._extract_param_names(current.strip()))
                current = ""
            else:
                current += char
        
        exclude = {'options', 'config', 'req', 'res', 'next', 'err', 'error', 
                   'callback', 'cb', 'this', 'self'}
        # FIX: Allow single letter params (e, t, n) for minified code
        params = [p for p in params if p not in exclude and len(p) >= 1]
        
        return params

    def _extract_param_names(self, param_str):
        """Extract variable names from parameter string"""
        names = []
        
        if param_str.startswith('{') and param_str.endswith('}'):
            inner = param_str[1:-1]
            parts = re.findall(r'(?:(\w+)\s*:\s*)?(\w+)', inner)
            for alias, name in parts:
                names.append(alias if alias else name)
        elif param_str.startswith('[') and param_str.endswith(']'):
            inner = param_str[1:-1]
            names.extend(re.findall(r'\w+', inner))
        elif '=' in param_str:
            base = param_str.split('=')[0].strip()
            names.append(base)
        else:
            match = re.match(r'^(\w+)', param_str)
            if match:
                names.append(match.group(1))
        
        return names

    def _map_variables(self, code):
        """Maps all variable definitions with enhanced object tracking"""
        var_pattern = re.compile(
            r'(?:const|let|var)\s+(\w+)\s*=\s*(\{)',
            re.MULTILINE
        )
        
        for match in var_pattern.finditer(code):
            var_name = match.group(1)
            start_brace = match.end() - 1
            end_brace = self._find_closing_brace(code, start_brace)
            
            if end_brace != -1:
                content = code[start_brace:end_brace+1]
                scope_name = self._get_scope_at_position(match.start())
                
                self.variable_map[var_name] = {
                    'value': content,
                    'pos': match.start(),
                    'scope': scope_name,
                    'type': 'object'
                }

    def _map_array_objects(self, code):
        """Enhanced array harvesting - captures arrays with object metadata"""
        array_pattern = re.compile(r'(?:const|let|var)\s+(\w+)\s*=\s*\[')
        
        for match in array_pattern.finditer(code):
            var_name = match.group(1)
            start_bracket = match.end() - 1
            end_bracket = self._find_closing_bracket(code, start_bracket)
            
            if end_bracket != -1:
                array_content = code[start_bracket:end_bracket+1]
                objects = self._extract_array_objects(array_content)
                
                if objects:
                    self.array_objects[var_name] = {
                        'objects': objects,
                        'pos': match.start()
                    }

    def _extract_array_objects(self, array_str):
        """Parse objects within an array string"""
        objects = []
        depth = 0
        current_obj = ""
        in_object = False
        
        for char in array_str:
            if char == '{':
                depth += 1
                in_object = True
                current_obj += char
            elif char == '}':
                depth -= 1
                current_obj += char
                if depth == 0 and in_object:
                    obj_data = self._parse_object_literal(current_obj)
                    if obj_data:
                        objects.append(obj_data)
                    current_obj = ""
                    in_object = False
            elif in_object:
                current_obj += char
        
        return objects

    def _parse_object_literal(self, obj_str):
        """Extract key-value pairs from object literal string"""
        result = {}
        inner = obj_str.strip()[1:-1]
        pairs = re.findall(r'(\w+)\s*:\s*([^,]+?)(?=,|\s*$)', inner, re.DOTALL)
        
        for key, value in pairs:
            value = value.strip()
            if value.startswith('{'):
                nested_keys = re.findall(r'(\w+)\s*:', value)
                result[key] = nested_keys
            else:
                result[key] = value.strip('\'"')
        
        return result

    def _find_closing_brace(self, code, start_index):
        """Finds matching closing brace with string awareness"""
        if start_index >= len(code) or code[start_index] != '{':
            return -1
            
        balance = 0
        in_string = False
        escape_next = False
        string_char = None
        
        for i in range(start_index, len(code)):
            char = code[i]
            
            if escape_next:
                escape_next = False
                continue
            
            if char == '\\':
                escape_next = True
                continue
            
            if char in ['"', "'", '`']:
                if not in_string:
                    in_string = True
                    string_char = char
                elif char == string_char:
                    in_string = False
                    string_char = None
                continue
            
            if not in_string:
                if char == '{':
                    balance += 1
                elif char == '}':
                    balance -= 1
                    if balance == 0:
                        return i
        
        return -1

    def _find_closing_bracket(self, code, start_index):
        """Finds matching closing bracket for arrays"""
        if start_index >= len(code) or code[start_index] != '[':
            return -1
            
        balance = 0
        in_string = False
        string_char = None
        
        for i in range(start_index, len(code)):
            char = code[i]
            
            if char in ['"', "'", '`']:
                if not in_string:
                    in_string = True
                    string_char = char
                elif char == string_char:
                    in_string = False
            
            if not in_string:
                if char == '[':
                    balance += 1
                elif char == ']':
                    balance -= 1
                    if balance == 0:
                        return i
        
        return -1

    def _get_scope_at_position(self, position):
        """Returns the name of the scope containing a position"""
        for scope in self.scopes:
            if scope['start'] <= position <= scope['end']:
                return scope.get('name', 'unknown')
        
        for class_scope in self.class_scopes:
            if class_scope['start'] <= position <= class_scope['end']:
                return class_scope.get('name', 'unknown')
        
        return 'global'

    def get_params_for_context(self, position):
        """
        Returns all parameters available at a specific code position.
        Finds the smallest enclosing function scope (tightest scope wins).
        """
        best_scope = None
        min_len = float('inf')
        
        for scope in self.scopes:
            if scope['start'] <= position <= scope['end']:
                scope_len = scope['end'] - scope['start']
                if scope_len < min_len:
                    min_len = scope_len
                    best_scope = scope
        
        if best_scope:
            return best_scope['params']
        
        return []

    def get_variable_definition(self, var_name):
        """Retrieves the full definition of a variable from anywhere in the file"""
        var_data = self.variable_map.get(var_name)
        if var_data:
            return var_data.get('value', '')
        return ''

    def get_variable_keys(self, var_name):
        """Extract keys from a variable's object definition"""
        definition = self.get_variable_definition(var_name)
        if definition:
            keys = re.findall(r'["\']?(\w+)["\']?\s*:', definition)
            return [k for k in keys if k not in {'type', 'name', 'value'}]
        return []

    def get_array_object_data(self, var_name):
        """Get structured data for array of objects"""
        return self.array_objects.get(var_name, {}).get('objects', [])
        
    def debug_print(self):
        """Utility for debugging"""
        print(f"\n  [ScopeManager Debug]")
        print(f"    Functions: {len(self.scopes)}")
        print(f"    Variables: {len(self.variable_map)}")

# ==============================================================================
# CLASS: ENHANCED VARIABLE RESOLVER
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
        self._compile_patterns()
    
    def _compile_patterns(self):
        self.pattern1 = re.compile(r'(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*["\']([^"\']{2,100}?)["\']')
        self.pattern2 = re.compile(r'this\.(url|serverURL|baseURL|apiURL|apiUrl|rootUrl|baseUrl)\s*=\s*["\']([^"\']{2,100}?)["\']')
        self.pattern3 = re.compile(r"this\.(url|serverURL|baseURL|apiURL)\s*=\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\[([\"'])([a-zA-Z_$][a-zA-Z0-9_$]*)\3\]")
        self.pattern4 = re.compile(r'this\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*["\']([^"\']{2,100}?)["\']')
        self.pattern5 = re.compile(r'\b([a-zA-Z_$][a-zA-Z0-9_$]{2,})\s*=\s*["\']([^"\']{2,100}?)["\']')
        self.pattern6 = re.compile(r'\b([a-z]{1,2})\s*=\s*["\']([^"\']{5,100}?)["\']')
        self.pattern7 = re.compile(r'(\w+)\s*:\s*["\']([^"\']{3,100}?)["\']')
        self.pattern8 = re.compile(r'["\']([/][^"\']{3,100}?)["\']\s*(?:,|])')
        
    def extract_all_variables(self, code, filename):
        file_vars = {}
        self._extract_method_definitions(code, filename)
        self._extract_obfuscated_strings(code, filename)
        self._extract_service_properties(code, filename, file_vars)
        for match in self.pattern1.finditer(code):
            var_name, var_value = match.group(1), match.group(2)
            if not self._is_noise_value(var_value): self._register_variable(var_name, var_value, filename, file_vars, 90)
        for match in self.pattern2.finditer(code):
            prop, var_value = match.group(1), match.group(2)
            if not self._is_noise_value(var_value):
                self._register_variable(f"this.{prop}", var_value, filename, file_vars, 98)
                self._register_variable(prop, var_value, filename, file_vars, 95)
                self.property_accesses[prop] = var_value
        for match in self.pattern3.finditer(code):
            prop, source_obj, source_prop = match.group(1), match.group(2), match.group(4)
            self.property_accesses[prop] = f"{source_obj}.{source_prop}"
        for match in self.pattern4.finditer(code):
            prop, var_value = match.group(1), match.group(2)
            if not self._is_noise_value(var_value):
                self._register_variable(f"this.{prop}", var_value, filename, file_vars, 95)
                self._register_variable(prop, var_value, filename, file_vars, 90)
                self.property_accesses[prop] = var_value
        for match in self.pattern5.finditer(code):
            var_name, var_value = match.group(1), match.group(2)
            if var_name not in file_vars and not self._is_noise_value(var_value):
                self._register_variable(var_name, var_value, filename, file_vars, 70)
        for match in self.pattern6.finditer(code):
            var_name, var_value = match.group(1), match.group(2)
            if self._is_url_like(var_value) and not self._is_noise_value(var_value):
                self._register_variable(var_name, var_value, filename, file_vars, 60)
        for match in self.pattern7.finditer(code):
            key, value = match.group(1), match.group(2)
            if self._is_url_like(value) and not self._is_noise_value(value):
                self._register_variable(key, value, filename, file_vars, 65)
        for match in self.pattern8.finditer(code):
            val = match.group(1)
            if self._is_url_like(val) and not self._is_noise_value(val):
                val_hash = hashlib.md5(val.encode()).hexdigest()[:8]
                self._register_variable(f"ARRAY_ITEM_{val_hash}", val, filename, file_vars, 60)
        self.file_variables[filename] = file_vars
        return file_vars
    
    def _extract_method_definitions(self, code, filename):
        pattern1 = re.compile(r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(\s*\)\s*\{(?:[^{}]|\{[^}]*\})*return\s+["\']([^"\']+)["\']', re.DOTALL)
        for match in pattern1.finditer(code):
            method_name, return_value = match.group(1), match.group(2)
            if self._is_url_like(return_value):
                self.methods[method_name] = return_value
                self.methods[f"this.{method_name}"] = return_value
        pattern2 = re.compile(r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(\s*\)\s*\{(?:[^{}]|\{[^}]*\})*return[^}]+\?[^:]+:(?:[^}]|\{[^}]*\})*["\']([^"\']+)["\']', re.DOTALL)
        for match in pattern2.finditer(code):
            method_name = match.group(1)
            ternary_section = code[match.start():match.end()]
            strings = re.findall(r'["\']([^"\']+)["\']', ternary_section)
            for s in strings:
                if self._is_url_like(s):
                    self.methods[method_name] = s
                    self.methods[f"this.{method_name}"] = s
                    break
        pattern3 = re.compile(r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(\s*\)\s*\{(?:[^{}]|\{[^}]*\})*return\s+location\.origin\s*\+\s*["\']([^"\']+)["\']', re.DOTALL)
        for match in pattern3.finditer(code):
            method_name, suffix = match.group(1), match.group(2)
            self.methods[method_name] = f"ORIGIN{suffix}"
            self.methods[f"this.{method_name}"] = f"ORIGIN{suffix}"
        pattern4 = re.compile(r'(?:apiUrl|baseUrl|serverUrl|apiEndpoint)\s*:\s*["\']([^"\']+)["\']', re.IGNORECASE)
        for match in pattern4.finditer(code):
            url = match.group(1)
            if self._is_url_like(url):
                self.methods['environmentApiUrl'] = url
    
    def _extract_service_properties(self, code, filename, file_vars):
        pattern = re.compile(r'this\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*this\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(\s*\)\s*\+\s*["\']([^"\']+)["\']')
        for match in pattern.finditer(code):
            property_name, method_name, path_suffix = match.group(1), match.group(2), match.group(3)
            method_result = self._resolve_method(method_name)
            if method_result:
                full_endpoint = method_result + path_suffix
                self.service_properties[property_name] = {'endpoint': full_endpoint, 'method_call': f"this.{method_name}()", 'suffix': path_suffix, 'source': filename}
                self._register_variable(property_name, full_endpoint, filename, file_vars, 95)
                self._register_variable(f"this.{property_name}", full_endpoint, filename, file_vars, 98)
    
    def _resolve_method(self, method_name):
        if method_name in self.methods: return self.methods[method_name]
        if f"this.{method_name}" in self.methods: return self.methods[f"this.{method_name}"]
        common_methods = {'getRootUrl': '/api', 'getBaseUrl': '/api', 'getApiUrl': '/api', 'getServerUrl': '/api', 'getApiBaseUrl': '/api'}
        if method_name in common_methods: return f"ORIGIN{common_methods[method_name]}"
        return None
    
    def _extract_obfuscated_strings(self, code, filename):
        pattern = re.compile(r'function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(\s*\)\s*\{[^}]*const\s+\w+\s*=\s*\[([^\]]+)\]', re.DOTALL)
        for match in pattern.finditer(code):
            func_name, array_content = match.group(1), match.group(2)
            strings = re.findall(r'["\']([^"\']+)["\']', array_content)
            for idx, string in enumerate(strings):
                if self._is_url_like(string) and not self._is_noise_value(string):
                    key = f"{func_name}_{idx}"
                    self.obfuscated_strings[key] = string
    
    def _is_noise_value(self, value):
        v = value.lower()
        for keyword in NOISE_KEYWORDS:
            if keyword in v: return True
        if len(value) < 2: return True
        return False
    
    def _register_variable(self, var_name, var_value, filename, file_vars, confidence):
        for pattern in BASE_URL_BLACKLIST:
            if re.search(pattern, var_value, re.IGNORECASE): return
        file_vars[var_name] = var_value
        if var_name not in self.variables or self.variables[var_name]['confidence'] < confidence:
            self.variables[var_name] = {'value': var_value, 'source_file': filename, 'confidence': confidence}
        if self._could_be_base_url(var_value): self.potential_bases[var_name] = var_value
        if self._is_base_url(var_value): self.global_scope[var_name] = var_value
    
    def _is_url_like(self, value):
        if len(value) < 2: return False
        return (value.startswith('http') or value.startswith('/') or value.startswith('#/') or value.startswith('ORIGIN') or
            any(term in value.lower() for term in ['api', 'endpoint', 'service', 'rest', 'graphql', 'fetch', 'data', 'dashboard', 'master', 'project']))
    
    def _could_be_base_url(self, value):
        if len(value) < 3: return False
        if not (value.startswith('http') or value.startswith('/') or value.startswith('#/') or value.startswith('ORIGIN')): return False
        for pattern in BASE_URL_BLACKLIST:
            if re.search(pattern, value, re.IGNORECASE): return False
        return True
    
    def _is_base_url(self, value):
        for pattern in BASE_URL_BLACKLIST:
            if re.search(pattern, value, re.IGNORECASE): return False
        if len(value) < 5: return False
        if not (value.startswith('http') or value.startswith('/') or value.startswith('#/') or value.startswith('ORIGIN')): return False
        patterns = [r'^https?://[^/]+', r'^/', r'^#/', r'^ORIGIN']
        return any(re.search(p, value) for p in patterns)
    
    def resolve(self, var_name):
        if var_name in self.variables: return self.variables[var_name]['value']
        if var_name in self.property_accesses: return self.property_accesses[var_name]
        if var_name in self.service_properties: return self.service_properties[var_name]['endpoint']
        return None
    
    def resolve_with_fallback(self, var_name):
        if var_name in self.global_scope: return self.global_scope[var_name]
        if var_name in self.potential_bases: return self.potential_bases[var_name]
        if var_name in self.variables: return self.variables[var_name]['value']
        if var_name in self.property_accesses: return self.property_accesses[var_name]
        if var_name in self.service_properties: return self.service_properties[var_name]['endpoint']
        if f"this.{var_name}" in self.variables: return self.variables[f"this.{var_name}"]['value']
        for prop in ['url', 'serverURL', 'baseURL', 'apiURL', 'rootUrl', 'baseUrl']:
            if var_name == prop and prop in self.property_accesses: return self.property_accesses[prop]
        return None
    
    def resolve_method_call(self, method_call_str):
        method_call_str = method_call_str.strip()
        if method_call_str.endswith('()'): method_call_str = method_call_str[:-2]
        if method_call_str in self.methods: return self.methods[method_call_str]
        if method_call_str.startswith('this.'):
            method_name = method_call_str[5:]
            if method_name in self.methods: return self.methods[method_name]
        else:
            if f"this.{method_call_str}" in self.methods: return self.methods[f"this.{method_call_str}"]
        return None
    
    def get_all_base_urls(self):
        return {**self.global_scope, **self.potential_bases, **self.property_accesses}
    
    def get_all_service_properties(self):
        return self.service_properties

# ==============================================================================
# CLASS: ENHANCED RPC EXTRACTOR WITH METHOD CALL SUPPORT
# ==============================================================================
class EnhancedRPCExtractor:
    """Extracts RPC-style endpoint definitions with method call support"""
    def __init__(self, resolver, scope_manager=None):
        self.resolver = resolver
        self.endpoints = []
        self.ultimate_extractor = UltimateParameterExtractor()
        self.scope_manager = scope_manager
    
    def extract_rpc_patterns(self, code, filename):
        found = []
        pattern_method = re.compile(r'this\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*this\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(\s*\)\s*\+\s*["\']([^"\']+)["\']')
        for match in pattern_method.finditer(code):
            property_name, method_name, suffix = match.group(1), match.group(2), match.group(3)
            if self._is_noise(method_name, suffix): continue
            base_url = self.resolver.resolve_method_call(f"this.{method_name}")
            if base_url:
                full_endpoint = base_url + suffix
                if self._is_valid_endpoint(full_endpoint):
                    method = self._guess_method_from_key(property_name)
                    # FIX: Use ultimate extractor
                    params_basic = self._extract_params_from_context(suffix, code, match.start())
                    params_rich = self.ultimate_extractor.extract_all_params(code, full_endpoint, match.start())
                    params_ultimate = []
                    for category in ['body', 'query', 'headers', 'path']:
                        for p in params_rich.get(category, []):
                            params_ultimate.append(p['name'] if isinstance(p, dict) else p)
                    all_params = list(set(params_basic + params_ultimate))
                    clean_params = self.ultimate_extractor.filter_list(all_params)

                    found.append({'endpoint': full_endpoint, 'method': method, 'parameters': clean_params, 'pattern': f'this.{property_name} = this.{method_name}() + "{suffix}"', 'key': property_name, 'type': 'RPC_METHOD_CALL', 'source': filename, 'classification': 'RPC_ENDPOINT', 'confidence': 98})
        
        pattern1 = re.compile(r'(\w+)\s*:\s*([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*\+\s*["\']([^"\']+)["\']')
        for match in pattern1.finditer(code):
            key, var_name, endpoint_suffix = match.group(1), match.group(2), match.group(3)
            if self._is_noise(var_name, endpoint_suffix): continue
            base_url = self.resolver.resolve_with_fallback(var_name)
            if base_url:
                full_endpoint = base_url + endpoint_suffix
                if self._is_valid_endpoint(full_endpoint):
                    method = self._guess_method_from_key(key)
                    # FIX: Use ultimate extractor
                    params_basic = self._extract_params_from_context(endpoint_suffix, code, match.start())
                    params_rich = self.ultimate_extractor.extract_all_params(code, full_endpoint, match.start())
                    params_ultimate = []
                    for category in ['body', 'query', 'headers', 'path']:
                        for p in params_rich.get(category, []):
                            params_ultimate.append(p['name'] if isinstance(p, dict) else p)
                    all_params = list(set(params_basic + params_ultimate))
                    clean_params = self.ultimate_extractor.filter_list(all_params)
                    found.append({'endpoint': full_endpoint, 'method': method, 'parameters': clean_params, 'pattern': f'{var_name} + "{endpoint_suffix}"', 'key': key, 'type': 'RPC_OBJECT_PROPERTY', 'source': filename, 'classification': 'RPC_ENDPOINT', 'confidence': 95})
        
        # Simplified patterns for brevity (rest are preserved logic)
        pattern2 = re.compile(r'(?:var|let|const)?\s*(\w+)\s*=\s*([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*\+\s*["\']([^"\']+)["\']')
        for match in pattern2.finditer(code):
            result_var, base_var, suffix = match.group(1), match.group(2), match.group(3)
            if self._is_noise(base_var, suffix): continue
            base_url = self.resolver.resolve_with_fallback(base_var)
            if base_url:
                full_endpoint = base_url + suffix
                if self._is_valid_endpoint(full_endpoint):
                    found.append({'endpoint': full_endpoint, 'method': 'GET', 'pattern': f'{base_var} + "{suffix}"', 'type': 'RPC_VARIABLE_CONCAT', 'source': filename, 'classification': 'RPC_ENDPOINT', 'confidence': 90})

        pattern3 = re.compile(r'`\$\{([a-zA-Z_$][a-zA-Z0-9_$.]*)\}([^`]+)`')
        for match in pattern3.finditer(code):
            var_name, suffix = match.group(1), match.group(2)
            if self._is_noise(var_name, suffix): continue
            base_url = self.resolver.resolve_with_fallback(var_name)
            if base_url:
                full_endpoint = base_url + suffix
                if self._is_valid_endpoint(full_endpoint):
                    found.append({'endpoint': full_endpoint, 'method': 'GET', 'pattern': f'`${{{var_name}}}{suffix}`', 'type': 'RPC_TEMPLATE_LITERAL', 'source': filename, 'classification': 'RPC_ENDPOINT', 'confidence': 85})

        pattern4 = re.compile(r'(?:get|post|put|delete|patch|fetch|postDataFromUrl|getDataFromUrl|postDataFromUrlWithoutSerialize|getDataFromUrlAndSendData|getRawDataFromUrl)\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*\+\s*["\']([^"\']+)["\']', re.IGNORECASE)
        for match in pattern4.finditer(code):
            var_name, suffix = match.group(1), match.group(2)
            if self._is_noise(var_name, suffix): continue
            base_url = self.resolver.resolve_with_fallback(var_name)
            if base_url:
                full_endpoint = base_url + suffix
                if self._is_valid_endpoint(full_endpoint):
                    ctx_before = code[max(0, match.start()-50):match.start()]
                    method = self._extract_method_from_context(ctx_before, code[match.start():match.start()+20])
                    # FIX: Use ultimate extractor
                    params_basic = self._extract_params_from_context(suffix, code, match.start())
                    params_rich = self.ultimate_extractor.extract_all_params(code, full_endpoint, match.start())
                    params_ultimate = []
                    for category in ['body', 'query', 'headers', 'path']:
                        for p in params_rich.get(category, []):
                            params_ultimate.append(p['name'] if isinstance(p, dict) else p)
                    all_params = list(set(params_basic + params_ultimate))
                    clean_params = self.ultimate_extractor.filter_list(all_params)
                    
                    found.append({'endpoint': full_endpoint, 'method': method, 'parameters': clean_params, 'pattern': f'{var_name} + "{suffix}"', 'type': 'RPC_HTTP_CALL', 'source': filename, 'classification': 'RPC_ENDPOINT', 'confidence': 95})

        return found

    def _extract_params_from_context(self, path_suffix, code, position):
        params = []
        path_params = re.findall(r'\{(\w+)\}', path_suffix)
        params.extend(path_params)
        if path_suffix.endswith('?'):
            context = code[position:min(len(code), position + 300)]
            query_params = re.findall(r'[?&](\w+)=', context)
            params.extend(query_params)
            params_match = re.search(r'params\s*:\s*\{([^}]+)\}', context)
            if params_match:
                obj_keys = re.findall(r'["\']?(\w+)["\']?\s*:', params_match.group(1))
                params.extend(obj_keys)

            # NEW: HttpParams pattern: .set('key', val)
            http_params = re.findall(r"\.set\(['\"](\w+)['\"]", context)
            params.extend(http_params)
        
        # ASK SCOPE MANAGER
        if self.scope_manager:
            scope_params = self.scope_manager.get_params_for_context(position)
            params.extend(scope_params)
        else:
            # Fallback
            context_before = code[max(0, position - 800):position]
            func_patterns = [
                r'(?:function\s+\w+|(\w+)\s*[:=]\s*(?:function)?|\w+)\s*\(([^)]*)\)\s*\{',
                r'(?:const|let|var)\s+\w+\s*=\s*\(([^)]*)\)\s*=>',
            ]
            
            closest_args = None
            last_match_pos = -1
            
            for p in func_patterns:
                for match in re.finditer(p, context_before):
                    if match.start() > last_match_pos:
                        last_match_pos = match.start()
                        closest_args = match.groups()[-1]
            
            if closest_args and closest_args.strip():
                arg_list = [a.strip() for a in closest_args.split(',') if a.strip()]
                for arg in arg_list:
                    arg_name = arg.split('=')[0].strip()
                    arg_name = arg_name.split(':')[0].strip()
                    if len(arg_name) > 1 and arg_name not in ['options', 'config', 'params']:
                        params.append(arg_name)
        
        params = list(set(params))
        params = self.ultimate_extractor.filter_list(params)
        return params
    
    def _is_valid_endpoint(self, endpoint):
        if not endpoint or len(endpoint) < 3: return False
        if ' ' in endpoint: return False
        if '${' in endpoint or '{{' in endpoint or '`' in endpoint: return False
        try:
            if endpoint.count('(') != endpoint.count(')') or endpoint.count('[') != endpoint.count(']') or endpoint.count('{') != endpoint.count('}'): return False
        except: return False
        if 'undefined' in endpoint.lower() or '/null' in endpoint or '/null/' in endpoint: return False
        for pattern in NOISE_PATTERNS:
            if re.search(pattern, endpoint, re.IGNORECASE): return False
        endpoint_lower = endpoint.lower()
        for keyword in NOISE_KEYWORDS:
            if keyword in endpoint_lower: return False
        if '/xl/' in endpoint_lower or 'worksheet' in endpoint_lower: return False
        if any(x in endpoint_lower for x in ['ngdirectivedef', 'ngpipedef', 'ngmoduledef', 'nginjectabledef', 'nginjectordef']): return False
        if endpoint.startswith('ORIGIN'): endpoint = endpoint.replace('ORIGIN', '/')
        if not (endpoint.startswith('http') or endpoint.startswith('/') or endpoint.startswith('#/')): return False
        if endpoint.startswith('http'):
            try:
                parsed = urllib.parse.urlparse(endpoint)
                if not parsed.netloc: return False
                if not parsed.path or parsed.path == '/': return False
                path_parts = [p for p in parsed.path.split('/') if p]
                if len(path_parts) == 1 and len(path_parts[0]) <= 2: return False
            except: return False
        valid_indicators = ['/', '.json', '.xml', '?', '=', 'api', 'get', 'post', 'update', 'delete', 'fetch']
        if not any(x in endpoint_lower for x in valid_indicators): return False
        if endpoint_lower.endswith(('.js', '.css', '.png', '.jpg', '.svg', '.woff', '.ttf', '.eot')): return False
        if '?' in endpoint:
            query_part = endpoint.split('?')[1] if len(endpoint.split('?')) > 1 else ''
            if query_part and not any(c.isalnum() for c in query_part): return False
        return True
    
    def _is_noise(self, var_name, suffix):
        combined = (var_name + suffix).lower()
        for keyword in NOISE_KEYWORDS:
            if keyword in combined: return True
        if len(suffix) < 2: return True
        if suffix.strip() in [':', '/', '?', '=', ',', '.', '-', '_']: return True
        if any(x in combined for x in ['caused by', 'valid digit', 'error', ' dis', ' jaj', ' jar', ' lup', ' rep', ' tup']): return True
        if any(x in suffix for x in ['${', '{{', '`', '\\n', '\\r']): return True
        if any(x in suffix for x in ['animation-timing', 'sheet ${', 'sheet,', 'sheet[', 'sheet(', 'sheet.']): return True
        if suffix.strip() and len(suffix.strip()) == 1: return True
        if suffix.strip() in ['px', 'ms', 'em', 'rem', 'vh', 'vw', 'pt', '%']: return True
        if suffix.strip().isupper() and '_' in suffix: return True
        return False
    
    def _guess_method_from_key(self, key):
        k = key.lower()
        if any(x in k for x in ['get', 'fetch', 'load', 'search', 'query', 'find', 'read', 'list', 'show', 'all']): return 'GET'
        elif any(x in k for x in ['post', 'create', 'add', 'insert', 'new', 'submit', 'send', 'save', 'upload']): return 'POST'
        elif any(x in k for x in ['put', 'update', 'modify', 'edit', 'change']): return 'PUT'
        elif any(x in k for x in ['delete', 'remove', 'destroy', 'drop']): return 'DELETE'
        elif any(x in k for x in ['patch']): return 'PATCH'
        return 'GET'
    
    def _extract_method_from_context(self, before, after):
        combined = (before + after).upper()
        for method in ['POST', 'PUT', 'DELETE', 'PATCH', 'GET']:
            if method in combined: return method
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
        self.scope_manager = ScopeManager()
        self.rpc_extractor = EnhancedRPCExtractor(self.resolver, self.scope_manager)
        self.analyzed_js_files = set()
        self.ultimate_extractor = UltimateParameterExtractor()

    def scan(self, js_urls, json_urls):
        print(f"\n[PHASE 2] Enhanced Analysis with Method Call Resolution")
        print(f"  Processing: {len(js_urls)} JS files, {len(json_urls)} JSON configs")
        
        # After analyzing all JS files, extract TypeScript interfaces
        ts_interface_params = defaultdict(list)
        
        js_contents = {}
        for i, url in enumerate(js_urls, 1):
            if i % 10 == 0: print(f"    Progress: [{i}/{len(js_urls)}]", end='\r')
            if any(x in url.lower() for x in LOW_VALUE_JS): continue
            try:
                r = self.session.get(url, timeout=10, verify=False)
                if r.status_code == 200:
                    filename = url.split('/')[-1]
                    js_contents[url] = r.text
                    
                    # Parse file scope first
                    self.scope_manager.parse_file(r.text, filename)
                    
                    self.resolver.extract_all_variables(r.text, filename)
                    self.analyzed_js_files.add(url)
                    
                    # NEW: Extract TS interfaces
                    interface_params = self.ultimate_extractor.extract_typescript_interfaces(r.text)
                    if interface_params:
                        ts_interface_params[url] = interface_params
            except: pass
        
        print(f"\n    [+] Extracted {len(self.resolver.variables)} unique variables")
        
        rpc_count = 0
        for url, code in js_contents.items():
            filename = url.split('/')[-1]
            rpc_endpoints = self.rpc_extractor.extract_rpc_patterns(code, filename)
            for ep in rpc_endpoints:
                full_url = self.normalizer.normalize(ep['endpoint'])
                self.add_endpoint(full_url, ep['method'], ep.get('parameters', []), ep['type'], ep['source'], ep['classification'], ep['confidence'])
                rpc_count += 1
            for var_name, var_data in self.resolver.variables.items():
                if var_name.startswith("ARRAY_ITEM_"):
                     full_url = self.normalizer.normalize(var_data['value'])
                     self.add_endpoint(full_url, "GET", [], "ARRAY_HARVEST", var_data['source_file'], "BACKEND_API", 60)

        print(f"    [+] Found {rpc_count} RPC-style endpoints")
        
        service_count = 0
        for prop_name, prop_data in self.resolver.service_properties.items():
            full_url = self.normalizer.normalize(prop_data['endpoint'])
            method = self._guess_method_from_key(prop_name)
            self.add_endpoint(full_url, method, [], 'SERVICE_PROPERTY', prop_data['source'], 'BACKEND_API', 97)
            service_count += 1
        
        print(f"    [+] Found {service_count} service property endpoints")
        
        self._enhance_array_harvested_endpoints()

        print(f"\n  [Step 4/4] Standard endpoint analysis...")
        for json_url in json_urls: self.analyze_json_config(json_url)
        for url, code in js_contents.items(): self.analyze_code(code, url)
        
        # Post-process endpoints with trailing '?'
        for endpoint in self.endpoints:
            if endpoint['endpoint'].endswith('?') and not endpoint['parameters']:
                potential_params = self._extract_query_params_from_url_with_questionmark(code, endpoint['endpoint'])
                if potential_params:
                    endpoint['parameters'] = self.ultimate_extractor.filter_list(potential_params)

        # Merge TS interface params into endpoints
        for endpoint in self.endpoints:
            for url, params in ts_interface_params.items():
                if endpoint['source'] in url:
                    existing = endpoint.get('parameters', [])
                    merged = list(set(existing + params))
                    endpoint['parameters'] = self.ultimate_extractor.filter_list(merged)

        print(f"\n  [+] Total endpoints discovered: {len(self.endpoints)}")
        
        if '--debug-scope' in sys.argv:
            self.scope_manager.debug_print()
            
        return self.endpoints

    def analyze_json_config(self, json_url):
        try:
            r = self.session.get(json_url, timeout=10, verify=False)
            if r.status_code == 200:
                self._extract_from_json(r.json(), json_url.split('/')[-1], json_url)
        except: pass

    def _extract_from_json(self, data, filename, source_url, path=''):
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                if isinstance(value, str):
                    if len(value) > 3 and not value.isspace():
                        method = self._guess_method_from_key(key)
                        classification = self._classify_json_value(value, key)
                        if classification != "NOISE":
                            self.add_endpoint(self.normalizer.normalize(value), method, [], "JSON_CONFIG", filename, classification, 75)
                elif isinstance(value, (dict, list)):
                    self._extract_from_json(value, filename, source_url, current_path)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                if isinstance(item, (dict, list)):
                    self._extract_from_json(item, filename, source_url, f"{path}[{i}]")

    def _classify_json_value(self, value, key):
        v, k = value.lower(), key.lower()
        for keyword in NOISE_KEYWORDS:
            if keyword in v: return "NOISE"
        if any(re.search(p, value) for p in NOISE_PATTERNS): return "NOISE"
        if any(re.search(p, value, re.IGNORECASE) for p in API_INDICATORS): return "BACKEND_API"
        api_key_indicators = ['api', 'endpoint', 'url', 'service', 'path', 'route', 'dashboard']
        if any(ind in k for ind in api_key_indicators):
            if value.startswith('/') or value.startswith('http') or value.startswith('#/'): return "BACKEND_API"
        if value.startswith('http'):
            if not any(d in v for d in IGNORED_DOMAINS): return "EXTERNAL_API"
        if (value.startswith('/') or value.startswith('#/')) and len(value) > 3:
            if '/' in value[1:] or '#' in value: return "FRONTEND_ROUTE"
        return "NOISE"

    def _guess_method_from_key(self, key):
        k = key.lower()
        if any(x in k for x in ['get', 'fetch', 'load', 'search', 'query', 'find', 'read', 'list']): return 'GET'
        elif any(x in k for x in ['post', 'create', 'add', 'insert', 'submit', 'send', 'save']): return 'POST'
        elif any(x in k for x in ['put', 'update', 'modify', 'edit', 'change']): return 'PUT'
        elif any(x in k for x in ['delete', 'remove', 'destroy', 'drop']): return 'DELETE'
        return 'GET'
    
    def _extract_post_body_from_code(self, code, position):
        """Extract POST body structure from code"""
        context = code[max(0, position-500):min(len(code), position+500)]
        body_pattern = r'\.post\s*\([^,]+,\s*\{([^}]+)\}'
        match = re.search(body_pattern, context)
        if match:
            body_content = match.group(1)
            keys = re.findall(r'["\']?(\w+)["\']?\s*:', body_content)
            return self.ultimate_extractor.filter_list(keys)
        return []
        
    def _extract_contextual_params(self, code, endpoint_url, position):
        """Ultra-intelligent parameter extraction with noise filtering"""
        start = max(0, position - 200)
        end = min(len(code), position + len(endpoint_url) + 300)
        context = code[start:end]
        var_name = None
        pattern1 = rf'{re.escape(endpoint_url)}["\']?\s*,\s*(\w+)'
        match = re.search(pattern1, context)
        if match: var_name = match.group(1)
        if not var_name:
            pattern2 = r'(?:body|data)\s*[:=]\s*(\w+)'
            match = re.search(pattern2, context)
            if match: var_name = match.group(1)
        if not var_name:
            pattern3 = rf'\.(?:post|put|patch)\s*\([^,]+,\s*(\w+)'
            match = re.search(pattern3, context)
            if match: var_name = match.group(1)
        if not var_name: return []
        params = self._trace_variable_definition(code, var_name, position)
        return self.ultimate_extractor.filter_list(params)

    def _extract_query_params_from_url_with_questionmark(self, code, endpoint_url):
        """
        Extract query params for URLs ending with '?' by searching context.
        Ultra-conservative to prevent false positives.
        """
        if not endpoint_url.endswith('?'):
            return []
        
        # Find all occurrences of this endpoint in code
        escaped_url = re.escape(endpoint_url)
        pattern = rf'{escaped_url}["\']?\s*[+]?\s*["\']?([^"\']+)["\']?'
        
        params = []
        for match in re.finditer(pattern, code):
            query_string = match.group(1).strip()
            
            # STRICT VALIDATION LAYER 1: Must look like query params
            if '=' not in query_string:
                continue
            if any(x in query_string for x in ['${', '{{', '? ', ': ', '!==', '===', '||', '&&']):
                continue
            if len(query_string) > 200:  # Too long = likely code
                continue
            
            # STRICT VALIDATION LAYER 4: Must not contain JS keywords in context
            query_lower = query_string.lower()
            if any(kw in query_lower for kw in ['function', 'return', 'if(', 'else', 'switch', 'case']):
                continue
                
            # Extract param names (only before '=')
            param_matches = re.findall(r'[&]?(\w+)=', query_string)
            
            # STRICT VALIDATION LAYER 5: Check each param name
            for param in param_matches:
                # Too short
                if len(param) < 2:
                    continue
                
                # JS keywords
                if param.lower() in ['var', 'let', 'const', 'if', 'else', 'for', 'do', 'while', 'return', 'function', 'class']:
                    continue
                
                # Framework noise
                if param in self.ultimate_extractor.framework_noise:
                    continue
                
                # Likely noise based on heuristics
                if self.ultimate_extractor._is_likely_noise(param):
                    continue
                    
                params.append(param)
        
        return list(set(params))

    def _enhance_array_harvested_endpoints(self):
        """
        Post-process array-harvested endpoints to extract parameters from array objects
        Uses ScopeManager's array_objects data
        """
        if not self.scope_manager:
            return
        
        for var_name, array_data in self.scope_manager.array_objects.items():
            for obj in array_data['objects']:
                # obj structure: {url: '/api/user', method: 'POST', body: ['name', 'email']}
                url = obj.get('url')
                method = obj.get('method', 'GET')
                
                if url:
                    # Extract parameters from body or params keys
                    params = []
                    if 'body' in obj and isinstance(obj['body'], list):
                        params.extend(obj['body'])
                    if 'params' in obj and isinstance(obj['params'], list):
                        params.extend(obj['params'])
                    
                    # Update existing endpoint or create new one
                    full_url = self.normalizer.normalize(url)
                    
                    # Find existing endpoint
                    for endpoint in self.endpoints:
                        if endpoint['endpoint'] == full_url and endpoint['method'] == method:
                            # Merge parameters
                            existing = endpoint.get('parameters', [])
                            endpoint['parameters'] = list(set(existing + params))
                            break
                    else:
                        # Create new endpoint if not found
                        if params:  # Only add if we found parameters
                            self.add_endpoint(
                                full_url,
                                method,
                                params,
                                'ARRAY_OBJECT_ENHANCED',
                                var_name,
                                'BACKEND_API',
                                75
                            )

    def _extract_function_signature_params(self, code, position):
        """Extract params from function signature"""
        return self.rpc_extractor._extract_params_from_context("?", code, position)

    def _trace_variable_definition(self, code, variable_name, search_pos):
        search_area = code[:search_pos]
        patterns = [rf'(?:let|const|var)\s+{re.escape(variable_name)}\s*=\s*\{{', rf'\b{re.escape(variable_name)}\s*=\s*\{{']
        match = None
        for pattern in patterns:
            matches = list(re.finditer(pattern, search_area))
            if matches:
                match = matches[-1]
                break
        if not match: return []
        content = self.ultimate_extractor._extract_balanced_braces(code[match.end() - 1:])
        if not content: return []
        keys = re.findall(r'["\']?(\w+)["\']?\s*:', content)
        return self.ultimate_extractor.filter_list(list(set([k for k in keys if len(k) >= 1])))

    def analyze_code(self, code, source):
        if any(x in source.lower() for x in LOW_VALUE_JS): return
        
        # Capture options object in HTTP calls
        http_options_pattern = r'this\.http\.(get|post|put|delete|patch)\s*\(\s*([^,]+?)(?:,\s*(\{[^}]*\}))?'
        for m in re.finditer(http_options_pattern, code, re.IGNORECASE):
            method, url_part, options_obj = m.group(1).upper(), m.group(2).strip().strip('"\''), m.group(3)
            full_url = self.normalizer.normalize(url_part)
            extra_params = []
            if options_obj:
                params_match = re.search(r'params\s*:\s*\{([^}]+)\}', options_obj)
                if params_match: extra_params.extend(re.findall(r'["\']?(\w+)["\']?\s*:', params_match.group(1)))
                headers_match = re.search(r'headers\s*:\s*\{([^}]+)\}', options_obj)
                if headers_match: 
                    header_keys = re.findall(r'["\']([A-Za-z-]+)["\']:\s*', headers_match.group(1))
                    extra_params.extend([h for h in header_keys if h.startswith('X-') or h == 'Authorization'])
            
            if method in ['POST', 'PUT', 'PATCH']:
                extra_params.extend(self._extract_post_body_from_code(code, m.start()))

            extra_params = self.ultimate_extractor.filter_list(extra_params)
            self.process(full_url, method, m.start(), code, source, "HTTP_THIS", "BACKEND_API", 95, extra_params)
        
        # Standard HTTP
        for m in re.finditer(r'\.http\.(get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]+)', code, re.IGNORECASE):
            self.process(self.normalizer.normalize(m.group(2)), m.group(1).upper(), m.start(), code, source, "HTTP", "BACKEND_API", 90)
        
        # Router patterns with arrays
        router_array_pattern = r'this\.router\.navigate(?:ByUrl)?\s*\(\s*\[([^\]]+)\]'
        for m in re.finditer(router_array_pattern, code, re.IGNORECASE):
            array_content = m.group(1)
            route_parts = re.findall(r'["\']([^"\']+)["\']', array_content)
            if route_parts:
                route_path = route_parts[0]
                options_match = re.search(r'\{([^}]+)\}', array_content)
                route_params = []
                if options_match:
                    param_keys = re.findall(r'["\']?(\w+)["\']?\s*:', options_match.group(1))
                    route_params = self.ultimate_extractor.filter_list(param_keys)
                self.add_endpoint(self.normalizer.normalize(route_path), 'GET', route_params, 'ROUTER_NAV_ARRAY', source, 'FRONTEND_ROUTE', 85)

        # Standard Router
        for m in re.finditer(r'this\.router\.navigate(?:ByUrl)?\s*\(\s*[\'"`]([^\'"`]+)', code, re.IGNORECASE):
            self.process(self.normalizer.normalize(m.group(1)), "GET", m.start(), code, source, "ROUTER_NAV_THIS", "FRONTEND_ROUTE", 85)
        
        # Location patterns
        for m in re.finditer(r'location\.origin\s*\+\s*["\']([^"\']+)["\']', code, re.IGNORECASE):
            clean = self._extract_clean_route(m.group(1))
            if clean: self.process(self.normalizer.normalize(clean), "GET", m.start(), code, source, "LOCATION_ORIGIN", "FRONTEND_ROUTE", 85)
        
        # Query string construction
        query_concat_pattern = r'([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*\+\s*["\']?\?(\w+)=["\']?\s*\+'
        for m in re.finditer(query_concat_pattern, code):
            base_url_expr, first_param = m.group(1).strip(), m.group(2)
            if 'this.' in base_url_expr: base_url = self.resolver.resolve_with_fallback(base_url_expr.replace('this.', ''))
            elif re.match(r'^\w+$', base_url_expr): base_url = self.resolver.resolve_with_fallback(base_url_expr)
            else: continue
            if not base_url: continue
            context = code[m.start():m.start() + 200]
            all_params = [first_param] + re.findall(r'[&"\'](\w+)=["\']?\s*\+', context)
            all_params = self.ultimate_extractor.filter_list(all_params)
            self.add_endpoint(self.normalizer.normalize(base_url), 'GET', list(set(all_params)), 'QUERY_STRING_CONSTRUCTION', source, 'BACKEND_API', 85)
            
        # ENHANCEMENT 1: Post-process endpoints with trailing '?'
        for endpoint in self.endpoints:
            if endpoint['endpoint'].endswith('?') and not endpoint['parameters']:
                potential_params = self._extract_query_params_from_url_with_questionmark(code, endpoint['endpoint'])
                if potential_params:
                    endpoint['parameters'] = self.ultimate_extractor.filter_list(potential_params)

    def analyze_code_from_dynamic(self, code, source):
        filename = source.split('/')[-1] if '/' in source else source
        self.resolver.extract_all_variables(code, filename)
        rpc_endpoints = self.rpc_extractor.extract_rpc_patterns(code, filename)
        for ep in rpc_endpoints:
            self.add_endpoint(self.normalizer.normalize(ep['endpoint']), ep['method'], ep.get('parameters', []), ep['type'] + '_DYNAMIC', ep['source'], ep['classification'], ep['confidence'])
        self.analyze_code(code, source)

    def _extract_clean_route(self, path):
        path = path.strip()
        if '+' in path: path = path.split('+')[0]
        if '(' in path: 
            parts = re.split(r'[()]', path)
            for part in parts:
                if '#/' in part:
                    path = part
                    break
        path = path.strip('"\'')
        if self._is_valid_route(path): return path
        return None
    
    def _is_valid_route(self, route):
        if not route: return False
        route_lower = route.lower()
        for keyword in NOISE_KEYWORDS:
            if keyword in route_lower: return False
        return ('#/' in route or route.startswith('/') or route.startswith('#/'))

    def process(self, url, method, pos, code, source, type, classification, confidence, extra_params=[]):
        if self.is_valid(url):
            params_original = self.extract_params(code, pos + len(url))
            params_contextual = self._extract_contextual_params(code, url, pos)
            rich_params = self.ultimate_extractor.extract_all_params(code, url, pos)
            params_ultimate = []
            for category in ['body', 'query', 'headers', 'path']:
                for p in rich_params.get(category, []):
                    params_ultimate.append(p['name'] if isinstance(p, dict) else p)
            
            all_params = list(set(params_original + params_contextual + params_ultimate + extra_params))
            noise_keywords = {'this', 'self', 'super', 'window', 'document', 'undefined', 'null'}
            clean_params = [p for p in self.ultimate_extractor.filter_list(all_params) if p not in noise_keywords]
            
            self.add_endpoint(url, method, clean_params, type, source, classification, confidence)

    def add_endpoint(self, url, method, params, type, source, classification, confidence):
        params = self.ultimate_extractor.filter_list(params) if params else []
        url = self._clean_url(url)
        if not url: return
        url_normalized = url.rstrip('/')
        url_lower = url_normalized.lower()
        for keyword in NOISE_KEYWORDS:
            if keyword in url_lower: return
        if any(re.search(p, url_normalized) for p in NOISE_PATTERNS): return
        try:
            parsed = urllib.parse.urlparse(url_normalized)
            if parsed.path and len(parsed.path.strip('/')) < 2: return
        except: pass
        
        for e in self.endpoints:
            existing_url = e['endpoint'].rstrip('/')
            if existing_url == url_normalized and e['method'] == method:
                e['parameters'] = list(set(e['parameters'] + params))
                if confidence > self.confidence_scores.get(f"{method}:{url_normalized}", 0):
                    e['type'], e['classification'] = type, classification
                    self.confidence_scores[f"{method}:{url_normalized}"] = confidence
                return
        
        self.endpoints.append({"endpoint": url, "method": method, "parameters": params, "type": type, "source": source if isinstance(source, str) else source.split('/')[-1][:80], "classification": classification})
        self.confidence_scores[f"{method}:{url_normalized}"] = confidence
    
    def _clean_url(self, url):
        url = str(url).strip()
        if url.startswith('ORIGIN'): url = url.replace('ORIGIN', '')
        if url.startswith('https://') and 'window.open' in url:
            match = re.search(r'location\.origin\s*\+\s*["\']([^"\']+)["\']', url)
            if match:
                path = match.group(1)
                clean_path = self._extract_clean_route(path)
                if clean_path: return self.normalizer.normalize(clean_path)
            return None
        url = url.replace('\"', '')
        if '(' in url and ')' in url and ('window.open' in url or 'location.origin' in url):
            match = re.search(r'["\']([^"\']+)["\']', url)
            if match: url = match.group(1)
        if ')' in url: url = url.split(')')[0]
        if ',' in url and '_self' in url: url = url.split(',')[0]
        return url

    def is_valid(self, url):
        if not url: return False
        url = url.strip()
        if len(url) < 3 or ' ' in url: return False
        url_lower = url.lower()
        for keyword in NOISE_KEYWORDS:
            if keyword in url_lower: return False
        if any(b in url.lower() for b in STRICT_BLOCKS): return False
        for p in FALSE_POSITIVE_PATTERNS:
            if re.search(p, url, re.IGNORECASE): return False
        if re.search(r'/[a-zA-Z]$', url): return False
        if re.search(r'/(?:px|ms|em|rem|vh|vw|pt)$', url): return False
        if any(x in url for x in ['${', '{{', '`', '\\n']): return False
        if '/undefined/' in url or '/null/' in url or url.endswith('/undefined') or url.endswith('/null'): return False
        if url.endswith('.js') and any(x in url_lower for x in ['ngdirectivedef', 'ngpipedef', 'ngmoduledef', 'nginjectabledef', 'nginjectordef']): return False
        if 'template.html' in url_lower: return False
        if '/xl/' in url_lower or 'worksheet' in url_lower: return False
        if any(x in url_lower for x in ['caused by:', 'valid digit', 'animation-timing-function']): return False
        if 'ON_PROPERTY' in url or 'ON_INIT' in url: return False
        if url.startswith('#/'): return True
        if url.lower().endswith(('.js', '.css', '.png', '.svg', '.woff', '.jpg', '.jpeg', '.gif', '.ico', '.ttf', '.eot', '.woff2')): return False
        return True

    def has_api_pattern(self, url):
        return any(re.search(p, url, re.IGNORECASE) for p in API_INDICATORS)

    def classify(self, url):
        u = url.lower()
        if self.has_api_pattern(url): return "BACKEND_API"
        if any(x in u for x in ['/login', '/dashboard', '/profile', '/#/', '/admin']): return "FRONTEND_ROUTE"
        if u.startswith('#/'): return "FRONTEND_ROUTE"
        if u.startswith('http'): return "EXTERNAL_API" if not any(d in u for d in IGNORED_DOMAINS) else "NOISE"
        if (u.startswith('/') or u.startswith('#/')) and len(u) > 3: return "FRONTEND_ROUTE"
        return "NOISE"

    def detect_method(self, code, pos):
        ctx = code[max(0, pos-200):min(len(code), pos+200)].upper()
        for m in ["POST", "PUT", "DELETE", "PATCH"]:
            if m in ctx: return m
        return "GET"

    def extract_params(self, code, pos):
        ctx = code[pos:pos+500]
        matches = re.findall(r'[{,]\s*["\']?([a-zA-Z0-9_]{1,20})["\']?\s*:', ctx)
        blacklist = {'var', 'let', 'const', 'if', 'else', 'true', 'false', 'null', 'this', 'return', 'switch', 'case', 'default', 'break', 'function', 'class', 'typeof', 'void', 'undefined', 'new', 'delete', 'in', 'instanceof', 'do', 'while', 'for', 'try', 'catch', 'finally', 'throw', 'export', 'import', 'from', 'as', 'async', 'await'}
        clean = []
        for p in matches:
            if p.lower() not in blacklist and len(p) >= 1: clean.append(p)
        return sorted(list(set(clean)))[:8]

# ==============================================================================
# FEDERATION HUNTER
# ==============================================================================
class EnhancedFederationHunter:
    def __init__(self, session, target_url):
        self.session = session
        self.target_url = target_url
        self.base_url = f"{urllib.parse.urlparse(target_url).scheme}://{urllib.parse.urlparse(target_url).netloc}"
        self.found_js_files = set()
        self.found_json_files = set()
        self.scan_queue = deque()
        self.swagger_endpoints = []

    def run(self):
        print(f"\n[PHASE 1] Discovery (JS + JSON + Swagger)")
        self.check_config_files()
        self.check_swagger_docs()
        self.crawl_html()
        print(f"  Deep scanning JavaScript files...")
        processed_files = set()
        scan_errors = 0
        while self.scan_queue:
            url = self.scan_queue.popleft()
            if url in processed_files: continue
            processed_files.add(url)
            if any(x in url.lower() for x in LOW_VALUE_JS): continue
            try:
                r = self.session.get(url, timeout=10, verify=False)
                if r.status_code == 200:
                    self.hunt_webpack_chunks(r.text, url)
                    self.hunt_config_references(r.text, url)
                elif r.status_code == 403:
                    print(f"\n  [!] 403 Forbidden on {url.split('/')[-1]} - Site may be blocking scraper")
                    scan_errors += 1
            except requests.exceptions.Timeout: scan_errors += 1
            except Exception as e:
                if scan_errors < 3: print(f"\n  [!] Error fetching {url.split('/')[-1]}: {type(e).__name__}")
                scan_errors += 1
        if scan_errors > 0: print(f"  [!] {scan_errors} files failed to download")
        print(f"  [+] JS: {len(self.found_js_files)}, JSON: {len(self.found_json_files)}")
        return list(self.found_js_files), list(self.found_json_files), self.swagger_endpoints

    def check_config_files(self):
        config_paths = ['/assets/config/environment.json', '/assets/config/config.json', '/config/environment.json', '/environment.json', '/config.json']
        for path in config_paths:
            url = urllib.parse.urljoin(self.base_url, path)
            try:
                r = self.session.get(url, timeout=8, verify=False)
                if r.status_code == 200:
                    try:
                        r.json()
                        self.found_json_files.add(url)
                        print(f"  [*] Found config: {path}")
                    except json.JSONDecodeError: pass
            except: pass

    def check_swagger_docs(self):
        swagger_paths = ['/swagger.json', '/api-docs', '/openapi.json', '/v2/api-docs', '/v3/api-docs', '/swagger/v1/swagger.json', '/api/swagger.json', '/api/v1/swagger.json']
        print(f"  Checking for Swagger/OpenAPI docs...")
        for path in swagger_paths:
            url = urllib.parse.urljoin(self.base_url, path)
            try:
                r = self.session.get(url, timeout=8, verify=False)
                if r.status_code == 200:
                    try:
                        swagger_data = r.json()
                        if 'paths' in swagger_data or 'openapi' in swagger_data or 'swagger' in swagger_data:
                            print(f"  [*] Found Swagger doc: {path}")
                            self.found_json_files.add(url)
                            if 'paths' in swagger_data: self._extract_swagger_endpoints(swagger_data, url)
                    except json.JSONDecodeError: pass
            except: pass

    def _extract_swagger_endpoints(self, swagger_data, source_url):
        paths = swagger_data.get('paths', {})
        base_url = swagger_data.get('basePath', '') or swagger_data.get('servers', [{}])[0].get('url', '')
        
        for path, methods in paths.items():
            if isinstance(methods, dict):
                for method, details in methods.items():
                    if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                        if base_url: full_url = urllib.parse.urljoin(self.base_url, base_url + path)
                        else: full_url = urllib.parse.urljoin(self.base_url, path)
                        
                        params = []
                        if isinstance(details, dict):
                            # 1. Path/Query Parameters
                            if 'parameters' in details:
                                for param in details['parameters']:
                                    if isinstance(param, dict) and 'name' in param:
                                        params.append(param['name'])
                            
                            # 2. Body Parameters (JSON Schema)
                            if 'requestBody' in details:
                                try:
                                    schema = details.get('requestBody', {}).get('content', {}).get('application/json', {}).get('schema', {})
                                    # Handle $ref (skip complex ref parsing for now, just look for properties)
                                    if 'properties' in schema:
                                        for prop_name, prop_schema in schema['properties'].items():
                                            params.append(prop_name)
                                            # RECURSIVE: Get nested properties
                                            if isinstance(prop_schema, dict) and 'properties' in prop_schema:
                                                for nested_name in prop_schema['properties'].keys():
                                                    params.append(f"{prop_name}.{nested_name}")
                                except:
                                    pass
                        
                        self.swagger_endpoints.append({"endpoint": full_url, "method": method.upper(), "parameters": list(set(params)), "type": "SWAGGER_DEF", "source": source_url, "classification": "VERIFIED_API", "confidence": 100})

    def _extract_params_from_schema(self, schema, depth=0, max_depth=3):
        """
        Recursively extract parameters from OpenAPI schema.
        Handles nested objects and arrays.
        """
        if depth > max_depth:
            return []
        
        params = []
        
        if not isinstance(schema, dict):
            return params
        
        # Handle $ref (schema references)
        if '$ref' in schema:
            # For now, skip refs to avoid complexity
            # In production, you'd resolve these
            return params
        
        # Handle object properties
        if 'properties' in schema:
            for prop_name, prop_schema in schema['properties'].items():
                # Add the property name
                params.append(prop_name)
                
                # If property is an object, recurse (with dot notation)
                if isinstance(prop_schema, dict):
                    prop_type = prop_schema.get('type', '')
                    
                    if prop_type == 'object':
                        nested_params = self._extract_params_from_schema(
                            prop_schema, 
                            depth + 1, 
                            max_depth
                        )
                        # Add nested params with dot notation
                        for nested in nested_params:
                            params.append(f"{prop_name}.{nested}")
                    
                    elif prop_type == 'array':
                        # Check if array items have properties
                        items = prop_schema.get('items', {})
                        if isinstance(items, dict) and 'properties' in items:
                            nested_params = self._extract_params_from_schema(
                                items,
                                depth + 1,
                                max_depth
                            )
                            for nested in nested_params:
                                params.append(f"{prop_name}.{nested}")
        
        # Handle allOf, anyOf, oneOf
        for combiner in ['allOf', 'anyOf', 'oneOf']:
            if combiner in schema:
                for sub_schema in schema[combiner]:
                    if isinstance(sub_schema, dict):
                        params.extend(self._extract_params_from_schema(
                            sub_schema,
                            depth + 1,
                            max_depth
                        ))
        
        return params

    def hunt_config_references(self, code, source_url):
        json_refs = re.findall(r'["\']([^"\']+\.json)["\']', code)
        base = source_url.rsplit('/', 1)[0] + '/'
        for ref in json_refs:
            if any(x in ref.lower() for x in ['sourcemap', 'webpack']): continue
            if ref.startswith('http'): full_url = ref
            elif ref.startswith('/'): full_url = urllib.parse.urljoin(self.base_url, ref)
            else: full_url = urllib.parse.urljoin(base, ref.lstrip('./'))
            if self.base_url in full_url and full_url not in self.found_json_files:
                try:
                    r = self.session.get(full_url, timeout=5, verify=False)
                    if r.status_code == 200:
                        try:
                            r.json()
                            self.found_json_files.add(full_url)
                        except json.JSONDecodeError: pass
                except: pass

    def hunt_webpack_chunks(self, code, source_url):
        suffix_match = re.search(r'\)\s*\+\s*["\']([^"\']+\.js)["\']', code)
        if suffix_match:
            suffix = suffix_match.group(1)
            candidates = re.finditer(r'["\']([\w-]+)["\']\s*:\s*["\']([^"\']+)["\']', code)
            base_url = source_url.rsplit('/', 1)[0] + '/'
            for match in candidates:
                val = match.group(2)
                if len(val) < 2 or len(val) > 100 or ' ' in val: continue
                clean_val = val.lstrip('./')
                if clean_val.startswith('/'): full_chunk_url = urllib.parse.urljoin(self.base_url, clean_val + suffix)
                else: full_chunk_url = urllib.parse.urljoin(base_url, clean_val + suffix)
                if full_chunk_url not in self.found_js_files:
                    self.found_js_files.add(full_chunk_url)
                    self.scan_queue.append(full_chunk_url)

    def crawl_html(self):
        print(f"  [*] Fetching HTML from {self.target_url}...")
        try:
            r = self.session.get(self.target_url, timeout=15, verify=False)
            print(f"  [*] Status Code: {r.status_code}")
            if r.status_code != 200: print(f"  [!] Non-200 status code. Content length: {len(r.text)}")
            soup = BeautifulSoup(r.text, 'html.parser')
            scripts = soup.find_all('script', src=True)
            print(f"  [*] Found {len(scripts)} script tags in HTML")
            if len(scripts) == 0:
                print(f"  [!] WARNING: No <script> tags found. This might be a dynamic SPA.")
                print(f"  [!] HTML preview (first 500 chars):\n      {r.text[:500]}")
            for s in scripts:
                url = urllib.parse.urljoin(self.target_url, s['src'])
                if not any(b in url for b in IGNORED_DOMAINS):
                    if url not in self.found_js_files:
                        self.found_js_files.add(url)
                        self.scan_queue.append(url)
        except requests.exceptions.SSLError as e: print(f"  [!] SSL Error: {e}\n  [!] Try adding verify=False or check SSL certificate")
        except requests.exceptions.ConnectionError as e: print(f"  [!] Connection Error: {e}\n  [!] Cannot reach target. Check internet connection.")
        except Exception as e: print(f"  [!] CRITICAL ERROR in crawl_html: {type(e).__name__}: {e}")

# ==============================================================================
# DYNAMIC INTERCEPTOR
# ==============================================================================
class DynamicInterceptor:
    def __init__(self, target_url, analyzer, cookies=None, max_routes=25, max_depth=3):
        self.target_url = target_url
        self.analyzer = analyzer
        self.domain = urllib.parse.urlparse(target_url).netloc
        self.base_url = f"{urllib.parse.urlparse(target_url).scheme}://{urllib.parse.urlparse(target_url).netloc}"
        self.cookies = cookies
        self.endpoints = []
        self.seen_requests = set()
        self.analyzed_js_files = set()
        self.discovered_routes = set()
        self.max_routes = max_routes
        self.max_depth = max_depth
        self.session_storage_data = {}
        self.local_storage_data = {}
        self.dynamic_params = {}
        self.extractor = UltimateParameterExtractor()

    def run(self, static_endpoints=[]):
        if not PLAYWRIGHT_AVAILABLE: 
            print(f"\n[PHASE 3] Playwright not available - skipping")
            return []
        print(f"\n[PHASE 3] Dynamic Discovery with Recursive Feedback Loop")
        for depth in range(1, self.max_depth + 1):
            print(f"\n  [Depth {depth}/{self.max_depth}] Navigating routes...")
            routes = self._get_routes_for_depth(static_endpoints, depth)
            if not routes:
                print(f"    No new routes at depth {depth}")
                break
            print(f"    Routes to visit: {len(routes)}")
            self._navigate_routes_with_feedback(routes, depth)
            print(f"    Analyzed {len(self.analyzed_js_files)} JS files so far")
            print(f"    Discovered {len(self.discovered_routes)} unique routes")
            print(f"    Captured {len(self.endpoints)} API calls")
        
        for endpoint in self.endpoints:
            ep_url = endpoint['endpoint'].split('?')[0]
            if ep_url in self.dynamic_params:
                existing_params = endpoint.get('parameters', [])
                new_params = self.dynamic_params[ep_url]
                endpoint['parameters'] = list(set(existing_params + new_params))
            
            # Use Ultimate Extractor to clean params
            if 'parameters' in endpoint:
                endpoint['parameters'] = self.extractor.filter_list(endpoint['parameters'])

        print(f"\n  [+] Total dynamic endpoints: {len(self.endpoints)}")
        print(f"  [+] Total JS files analyzed: {len(self.analyzed_js_files)}")
        return self.endpoints

    def _get_routes_for_depth(self, static_endpoints, depth):
        routes = []
        if depth == 1:
            routes = [self.target_url]
            for e in static_endpoints:
                if e['classification'] == 'FRONTEND_ROUTE':
                    clean = self._clean_route(e['endpoint'])
                    if clean and clean not in routes: routes.append(clean)
        else:
            routes = list(self.discovered_routes)
            for e in self.analyzer.endpoints:
                if e['classification'] == 'FRONTEND_ROUTE':
                    clean = self._clean_route(e['endpoint'])
                    if clean and clean not in self.discovered_routes: routes.append(clean)
        return self._prioritize_routes(routes, depth)[:self.max_routes]

    def _clean_route(self, endpoint):
        if not endpoint: return None
        clean = endpoint.replace('"', '').replace("'", "").strip()
        if 'undefined' in clean.lower() or '/null' in clean or '/null/' in clean: return None
        if '${' in clean or '{{' in clean or '`' in clean: return None
        if ' ' in clean: return None
        if any(x in clean.lower() for x in ['ngdirectivedef', 'ngpipedef', 'ngmoduledef', 'template.html', '/xl/']): return None
        if clean.startswith('http'): full = clean
        elif clean.startswith('/'): full = urllib.parse.urljoin(self.base_url, clean)
        else: return None
        if self.domain in full: return full
        return None

    def _prioritize_routes(self, routes, depth):
        def route_score(route):
            score = 0
            if '#/' in route: score += 100
            score += route.count('/') * 10
            if any(keyword in route.lower() for keyword in ['dashboard', 'admin', 'user', 'profile', 'settings', 'manage', 'list', 'view', 'edit']): score += 50
            if re.search(r'/\d+$', route) or re.search(r'/:[\w]+', route): score -= 30
            return score
        return sorted(routes, key=route_score, reverse=True)

    def _navigate_routes_with_feedback(self, routes, depth):
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True, viewport={'width': 1920, 'height': 1080})
            if self.cookies:
                context.add_cookies([{"name": k, "value": v, "domain": self.domain, "path": "/"} for k, v in self.cookies.items()])
            page = context.new_page()
            page.route("**/*", self._handle_request_interception)
            page.on("response", self._handle_response)
            for i, route in enumerate(routes, 1):
                print(f"      [{i}/{len(routes)}] {route[:80]}", end='\r')
                try:
                    response = page.goto(route, wait_until="networkidle", timeout=20000)
                    if response and 'login' in page.url.lower() and 'login' not in route.lower():
                        print(f"\n      [!] Redirected to login, skipping further routes at this depth")
                        break
                    self._extract_routes_from_page(page)
                    time.sleep(0.5)
                    self._extract_storage_data(page)
                except Exception: continue
            print()
            browser.close()

    def _extract_routes_from_page(self, page):
        try:
            links = page.query_selector_all('a[href]')
            for link in links[:50]:
                try:
                    href = link.get_attribute('href')
                    if href:
                        clean = self._clean_route(href)
                        if clean and clean not in self.discovered_routes: self.discovered_routes.add(clean)
                except: pass
            spa_links = page.query_selector_all('[routerlink], [ui-sref], [ng-href], [to]')
            for link in spa_links[:50]:
                try:
                    for attr in ['routerlink', 'ui-sref', 'ng-href', 'to']:
                        value = link.get_attribute(attr)
                        if value:
                            clean = self._clean_route(value)
                            if clean and clean not in self.discovered_routes: self.discovered_routes.add(clean)
                except: pass
        except: pass

    def _extract_storage_data(self, page):
        try:
            local_storage = page.evaluate('() => { return JSON.stringify(localStorage); }')
            session_storage = page.evaluate('() => { return JSON.stringify(sessionStorage); }')
            if local_storage: self.local_storage_data = json.loads(local_storage)
            if session_storage: self.session_storage_data = json.loads(session_storage)
        except: pass

    def _handle_response(self, response):
        url = response.url
        if any(b in url for b in IGNORED_DOMAINS): return
        if url in self.seen_requests: return
        self.seen_requests.add(url)
        try:
            content_type = response.headers.get("content-type", "").lower()
            if url.endswith('.js') or "javascript" in content_type:
                if url not in self.analyzer.analyzed_js_files:
                    self.analyzer.analyzed_js_files.add(url)
                    self.analyzed_js_files.add(url)
                    try:
                        code = response.text()
                        if len(code) > 100: self.analyzer.analyze_code_from_dynamic(code, url)
                    except: pass
            elif "application/json" in content_type:
                try:
                    endpoint = url.split('?')[0]
                    # FIX: Merge dynamic body params
                    params_query = []
                    parsed = urllib.parse.urlparse(url)
                    if parsed.query: params_query.extend(urllib.parse.parse_qs(parsed.query).keys())
                    
                    params_body = self.dynamic_params.get(endpoint, [])
                    all_params = list(set(params_query + params_body))
                    all_params = self.extractor.filter_list(all_params)
                    
                    self.endpoints.append({"endpoint": endpoint, "method": "GET", "parameters": all_params, "type": "DYNAMIC_API_CALL", "source": "Browser", "classification": "VERIFIED_API"})
                except: pass
            elif "text/html" in content_type:
                try:
                    html = response.text()
                    hash_routes = re.findall(r'href=["\']([^"\']*#/[^"\']+)["\']', html)
                    for route in hash_routes:
                        clean = self._clean_route(route)
                        if clean and clean not in self.discovered_routes: self.discovered_routes.add(clean)
                except: pass
        except: pass

    def _handle_request_interception(self, route):
        request = route.request
        method = request.method
        url = request.url
        if method in ['POST', 'PUT', 'PATCH']:
            try:
                content_type = request.headers.get('content-type', '').lower()
                if 'application/json' in content_type:
                    try:
                        data = request.post_data_json
                        if not data and request.post_data: data = json.loads(request.post_data)
                        if data:
                            keys = self._extract_keys_recursive(data)
                            keys = self.extractor.filter_list(keys)
                            endpoint = url.split('?')[0]
                            if endpoint not in self.dynamic_params: self.dynamic_params[endpoint] = []
                            self.dynamic_params[endpoint].extend(keys)
                    except: pass
                elif 'application/x-www-form-urlencoded' in content_type:
                    try:
                        post_data = request.post_data
                        if post_data:
                            params = post_data.split('&')
                            keys = [p.split('=')[0] for p in params if '=' in p]
                            endpoint = url.split('?')[0]
                            if endpoint not in self.dynamic_params: self.dynamic_params[endpoint] = []
                            self.dynamic_params[endpoint].extend(keys)
                    except: pass
            except: pass
        route.continue_()

    def _extract_keys_recursive(self, data, keys=None):
        if keys is None: keys = []
        if isinstance(data, dict):
            for key, value in data.items():
                keys.append(key)
                if isinstance(value, (dict, list)): self._extract_keys_recursive(value, keys)
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, (dict, list)): self._extract_keys_recursive(item, keys)
        return list(set(keys))

# ==============================================================================
# MAIN & REPORTING
# ==============================================================================
def json_to_excel(input_file, output_file):
    if not PANDAS_AVAILABLE:
        print("\n[!] Pandas not installed. Skipping Excel conversion.")
        return
    current_dir = os.getcwd()
    input_path = os.path.join(current_dir, input_file)
    output_path = os.path.join(current_dir, output_file)
    print(f"\n[PHASE 5] Excel Conversion")
    if not os.path.exists(input_path): return
    try:
        with open(input_path, 'r') as f: data = json.load(f)
        endpoints = data.get('endpoints', []) if isinstance(data, dict) else data
        rows = []
        for item in endpoints:
            params = item.get('parameters', [])
            params_formatted = ", ".join(params) if isinstance(params, list) else str(params)
            rows.append({"Endpoint": item.get('endpoint', ''), "Method": item.get('method', 'GET'), "Parameters": params_formatted, "Source File": item.get('source', 'Unknown'), "Type": item.get('type', ''), "Classification": item.get('classification', '')})
        df = pd.DataFrame(rows)
        with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='API_Endpoints')
            worksheet = writer.sheets['API_Endpoints']
            for column in df:
                col_idx = df.columns.get_loc(column) + 1
                worksheet.column_dimensions[chr(64 + col_idx)].width = 25 
        print(f"  [+] SUCCESS! Created: {output_file}")
    except Exception as e: print(f"  [X] ERROR Converting to Excel: {str(e)}")

def save_report(static, dynamic, filename="results.json"):
    print(f"\n[PHASE 4] Generating Report")
    combined = {}
    for item in static + dynamic:
        key = f"{item['method']}:{item['endpoint']}"
        if key not in combined: combined[key] = item
        else:
            combined[key]['parameters'] = list(set(combined[key]['parameters'] + item['parameters']))
            if item['type'].startswith('DYNAMIC'):
                combined[key]['type'] = item['type']
                combined[key]['classification'] = 'VERIFIED_API'
    results = []
    for item in combined.values():
        if item['classification'] == "NOISE": continue
        endpoint = item['endpoint']
        endpoint_lower = endpoint.lower()
        is_garbage = False
        if any(x in endpoint for x in ['${', '{{', '`', '\\n', '\\r']): is_garbage = True
        if ' ' in endpoint.split('?')[0]: is_garbage = True
        if re.search(r'/[a-zA-Z]$', endpoint): is_garbage = True
        if re.search(r'/(?:px|ms|em|rem|vh|vw|pt)$', endpoint): is_garbage = True
        if any(x in endpoint_lower for x in ['ngdirectivedef', 'ngpipedef', 'ngmoduledef', 'nginjectabledef', 'nginjectordef', 'template.html']): is_garbage = True
        if '/xl/' in endpoint_lower or 'worksheet' in endpoint_lower: is_garbage = True
        if any(x in endpoint_lower for x in ['caused by:', 'valid digit', 'animation-timing']): is_garbage = True
        if endpoint.rstrip('/').endswith(':'): is_garbage = True
        if '/undefined' in endpoint or '/null/' in endpoint: is_garbage = True
        if 'ON_PROPERTY' in endpoint or 'ON_INIT' in endpoint: is_garbage = True
        if 'vimeo.com' in endpoint_lower or 'vzaar.com' in endpoint_lower: is_garbage = True
        if not is_garbage: results.append(item)
    
    results.sort(key=lambda x: ({"VERIFIED_API": 0, "RPC_METHOD_CALL": 1, "SERVICE_PROPERTY": 2, "RPC_ENDPOINT": 3, "BACKEND_API": 4, "JSON_CONFIG": 5, "OPEN_REDIRECT_SINK": 6, "FRONTEND_ROUTE": 7, "EXTERNAL_API": 8}.get(x['classification'], 9), x['endpoint']))
    report = {"scan_metadata": {"scanner": "Advanced Endpoint Scanner - Enhanced Edition", "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"), "total_endpoints": len(results)}, "summary": {"verified_runtime": len([x for x in results if x['classification'] == "VERIFIED_API"]), "dynamic_discovered": len([e for e in results if 'DYNAMIC' in e.get('type', '')]), "rpc_method_calls": len([e for e in results if 'RPC_METHOD_CALL' in e.get('type', '')]), "backend": len([x for x in results if x['classification'] == "BACKEND_API"])}, "endpoints": results}
    with open(filename, "w") as f: json.dump(report, f, indent=2)
    print(f"\n{'='*70}\nSCAN COMPLETE\n{'='*70}\n  Total Endpoints: {len(results)}\n  [*] Verified Runtime APIs: {report['summary']['verified_runtime']}\n\n[FILE] JSON saved: {filename}")
    json_to_excel(filename, 'results.xlsx')

def parse_args():
    parser = argparse.ArgumentParser(description='Advanced Endpoint Scanner - Enhanced Edition', formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--target', type=str, help='Target URL')
    parser.add_argument('--no-cookies', action='store_true', help='Skip cookie input')
    parser.add_argument('--output', type=str, default='results.json', help='Output file path')
    parser.add_argument('--max-routes', type=int, default=25, help='Max routes to visit per depth')
    parser.add_argument('--max-depth', type=int, default=3, help='Max navigation depth')
    parser.add_argument('--quiet', action='store_true', help='Suppress progress output')
    return parser.parse_args()

if __name__ == "__main__":
    print("=" * 70 + "\nADVANCED ENDPOINT SCANNER - ENHANCED EDITION\nRecursive lazy-loading discovery for modern SPAs\n" + "=" * 70 + "\n")
    try:
        args = parse_args()
        if args.target: target = args.target
        else:
            target = input("Target URL: ").strip()
            if not target: sys.exit(1)
        if not target.startswith("http"): target = "https://" + target
        
        print(f"\n[DEBUG] Testing connection to {target}...")
        try:
            requests.get(target, timeout=10, verify=False)
            print(f"[DEBUG] ✓ Connection successful")
        except Exception as e:
            print(f"[X] FATAL: Cannot connect to target: {e}")
            sys.exit(1)
        
        cookies = {}
        if not args.no_cookies and not args.target:
            if input("\nAdd cookies? (y/n): ").strip().lower() == 'y':
                print("Enter cookies (press Enter with empty name to finish):")
                while True:
                    name = input("  Cookie name: ").strip()
                    if not name: break
                    value = input("  Cookie value: ").strip()
                    cookies[name] = value
        
        session = requests.Session()
        session.cookies.update(cookies)
        session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36', 'Upgrade-Insecure-Requests': '1'})
        
        start_time = time.time()
        hunter = EnhancedFederationHunter(session, target)
        js_files, json_files, swagger_endpoints = hunter.run()
        
        analyzer = EnhancedStaticAnalyzer(session, target)
        static_endpoints = analyzer.scan(js_files, json_files)
        if swagger_endpoints:
            print(f"\n[+] Merging {len(swagger_endpoints)} Swagger endpoints...")
            static_endpoints.extend(swagger_endpoints)
            
        interceptor = DynamicInterceptor(target, analyzer, cookies, max_routes=args.max_routes, max_depth=args.max_depth)
        dynamic_endpoints = interceptor.run(static_endpoints)
        static_endpoints.extend(analyzer.endpoints)
        
        elapsed = time.time() - start_time
        print(f"\n[TIME] Total scan time: {elapsed:.1f}s")
        save_report(static_endpoints, dynamic_endpoints, args.output)
        
    except KeyboardInterrupt: print("\n\n[X] Scan interrupted by user"); sys.exit(1)
    except Exception as e: print(f"\n\n[X] Fatal error: {e}"); import traceback; traceback.print_exc(); sys.exit(1)