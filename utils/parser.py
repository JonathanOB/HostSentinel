import re

FAILED_PASSWORD_RE = re.compile(
    r'Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)'
)
FAILED_PUBKEY_RE = re.compile(
    r'Failed publickey for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)'
)
ACCEPTED_PASSWORD_RE = re.compile(
    r'Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)'
)
ACCEPTED_PUBKEY_RE = re.compile(
    r'Accepted publickey for (\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)'
)
INVALID_USER_RE = re.compile(
    r'Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)'
)
USERADD_RE = re.compile(
    r'useradd\[.*?\]: new user: name=(\S+).*?uid=(\d+)'
)
GROUPADD_RE = re.compile(
    r'groupadd\[.*?\]: new group: name=(\S+)'
)
USERMOD_RE = re.compile(
    r'usermod\[.*?\].*?name=(\S+)'
)
SUDO_RE = re.compile(
    r'sudo:\s+(\S+)\s*:.*?; USER=(\S+)\s*; COMMAND=(.*)'
)
SU_SUCCESS_RE = re.compile(
    r'su\[.*?\]: \+ .* (\S+):(\S+)'
)
ROOT_LOGIN_RE = re.compile(
    r'ROOT LOGIN.*?from (\S+)'
)


def parse_auth_line(line: str) -> dict | None:
    m = FAILED_PASSWORD_RE.search(line)
    if m:
        return {
            'event_type': 'FAILED_SSH',
            'severity': 'MEDIUM',
            'username': m.group(1),
            'source_ip': m.group(2),
            'details': f"Failed password for '{m.group(1)}' from {m.group(2)}:{m.group(3)}",
            'raw_log': line.strip(),
        }

    m = FAILED_PUBKEY_RE.search(line)
    if m:
        return {
            'event_type': 'FAILED_SSH',
            'severity': 'LOW',
            'username': m.group(1),
            'source_ip': m.group(2),
            'details': f"Failed publickey for '{m.group(1)}' from {m.group(2)}:{m.group(3)}",
            'raw_log': line.strip(),
        }

    m = ACCEPTED_PASSWORD_RE.search(line)
    if m:
        return {
            'event_type': 'SUCCESSFUL_SSH',
            'severity': 'INFO',
            'username': m.group(1),
            'source_ip': m.group(2),
            'details': f"SSH login: '{m.group(1)}' from {m.group(2)}:{m.group(3)}",
            'raw_log': line.strip(),
        }

    m = ACCEPTED_PUBKEY_RE.search(line)
    if m:
        return {
            'event_type': 'SUCCESSFUL_SSH',
            'severity': 'INFO',
            'username': m.group(1),
            'source_ip': m.group(2),
            'details': f"SSH pubkey login: '{m.group(1)}' from {m.group(2)}:{m.group(3)}",
            'raw_log': line.strip(),
        }

    m = INVALID_USER_RE.search(line)
    if m:
        return {
            'event_type': 'FAILED_SSH',
            'severity': 'LOW',
            'username': m.group(1),
            'source_ip': m.group(2),
            'details': f"Login attempt for non-existent user '{m.group(1)}' from {m.group(2)}",
            'raw_log': line.strip(),
        }

    m = USERADD_RE.search(line)
    if m:
        return {
            'event_type': 'NEW_USER',
            'severity': 'HIGH',
            'username': m.group(1),
            'source_ip': None,
            'details': f"New user created: '{m.group(1)}' (uid={m.group(2)})",
            'raw_log': line.strip(),
        }

    m = GROUPADD_RE.search(line)
    if m:
        return {
            'event_type': 'GROUP_CHANGE',
            'severity': 'MEDIUM',
            'username': m.group(1),
            'source_ip': None,
            'details': f"New group created: '{m.group(1)}'",
            'raw_log': line.strip(),
        }

    m = USERMOD_RE.search(line)
    if m:
        return {
            'event_type': 'USER_MODIFIED',
            'severity': 'HIGH',
            'username': m.group(1),
            'source_ip': None,
            'details': f"User account modified: '{m.group(1)}'",
            'raw_log': line.strip(),
        }

    m = SU_SUCCESS_RE.search(line)
    if m:
        return {
            'event_type': 'PRIVILEGE_ESCALATION',
            'severity': 'HIGH',
            'username': m.group(1),
            'source_ip': None,
            'details': f"su: '{m.group(1)}' switched to '{m.group(2)}'",
            'raw_log': line.strip(),
        }

    m = SUDO_RE.search(line)
    if m:
        return {
            'event_type': 'SUDO_COMMAND',
            'severity': 'MEDIUM',
            'username': m.group(1),
            'source_ip': None,
            'details': f"sudo by '{m.group(1)}' as {m.group(2)}: {m.group(3).strip()}",
            'raw_log': line.strip(),
        }

    m = ROOT_LOGIN_RE.search(line)
    if m:
        return {
            'event_type': 'ROOT_LOGIN',
            'severity': 'HIGH',
            'username': 'root',
            'source_ip': None,
            'details': f"Root console login from {m.group(1)}",
            'raw_log': line.strip(),
        }

    return None
