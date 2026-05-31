import socket
import logging
import subprocess
import threading
import requests

logger = logging.getLogger(__name__)

_cache: dict = {}
_CACHE_MAX = 2000  # ~2 KB per entry → ~4 MB max
_pending: set = set()
_pending_lock = threading.Lock()

HOSTING_KEYWORDS = [
    'ovh', 'digitalocean', 'linode', 'vultr', 'hetzner',
    'amazon', 'aws', 'google', 'azure', 'alibaba', 'choopa',
    'zayo', 'cogent', 'leaseweb', 'serverius', 'frantech',
]


def get_ip_intel(ip: str, config: dict = None) -> dict:
    if ip in _cache:
        return _cache[ip]

    with _pending_lock:
        if ip in _pending:
            return {'ip': ip, 'country': None, 'country_code': None,
                    'city': None, 'org': None, 'hostname': None,
                    'whois_summary': None, 'threat_score': 0}
        _pending.add(ip)

    try:
        intel = {'ip': ip, 'country': None, 'country_code': None,
                 'city': None, 'org': None, 'hostname': None,
                 'whois_summary': None, 'threat_score': 0}

        # GeoIP via ip-api.com (free, 45 req/min)
        try:
            resp = requests.get(
                f'http://ip-api.com/json/{ip}',
                params={'fields': 'status,country,countryCode,city,org,isp,as'},
                timeout=5
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get('status') == 'success':
                    intel['country'] = data.get('country')
                    intel['country_code'] = data.get('countryCode')
                    intel['city'] = data.get('city')
                    intel['org'] = data.get('org') or data.get('isp') or data.get('as')
        except Exception as e:
            logger.debug(f"GeoIP lookup failed for {ip}: {e}")

        # Reverse DNS — capped at 3s; gethostbyaddr blocks indefinitely on Windows
        # for IPs with no PTR record, which stalls the enrichment thread
        try:
            _rdns_result = [None]
            def _rdns():
                try:
                    _rdns_result[0] = socket.gethostbyaddr(ip)[0]
                except Exception:
                    pass
            _t = threading.Thread(target=_rdns, daemon=True)
            _t.start()
            _t.join(3.0)
            intel['hostname'] = _rdns_result[0]
        except Exception:
            pass

        # WHOIS summary
        try:
            result = subprocess.run(
                ['whois', ip],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                keep = []
                for line in result.stdout.splitlines():
                    lower = line.lower()
                    if any(k in lower for k in
                           ('netname:', 'orgname:', 'org-name:', 'descr:',
                            'country:', 'abuse-mailbox:', 'address:')):
                        keep.append(line.strip())
                    if len(keep) >= 8:
                        break
                intel['whois_summary'] = '\n'.join(keep) if keep else None
        except Exception as e:
            logger.debug(f"whois failed for {ip}: {e}")

        # Threat scoring
        score = 0
        org_lower = (intel.get('org') or '').lower()
        if any(k in org_lower for k in HOSTING_KEYWORDS):
            score += 30
        if intel.get('hostname'):
            h = intel['hostname'].lower()
            if any(k in h for k in ('scan', 'crawl', 'spider', 'bot', 'probe')):
                score += 40
        intel['threat_score'] = min(score, 100)

        if len(_cache) >= _CACHE_MAX:
            _cache.pop(next(iter(_cache)))
        _cache[ip] = intel
        return intel
    finally:
        with _pending_lock:
            _pending.discard(ip)
