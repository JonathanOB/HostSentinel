import time
import secrets
import threading
from flask import (Blueprint, render_template, redirect, url_for,
                   request, flash, session)
from flask_login import (login_user, logout_user, login_required,
                         current_user, UserMixin)

from config import get_config
from utils.db import (get_recent_events, get_dashboard_stats, get_top_attackers,
                      get_attacker, get_honeypot_hits, get_file_integrity_status,
                      acknowledge_event, get_honeypot_stats,
                      get_record_counts, reset_database, get_all_ports)

dashboard_bp = Blueprint('dashboard', __name__)

# ── Login rate limiting ───────────────────────────────────────────────────────
_rate_lock = threading.Lock()
_login_log: dict = {}       # ip -> [timestamp, ...]
_MAX_ATTEMPTS = 5
_WINDOW_SEC   = 300         # 5 minutes
_LOCKOUT_SEC  = 900         # 15 minutes


def _is_locked_out(ip: str) -> bool:
    now = time.monotonic()
    with _rate_lock:
        times = _login_log.get(ip, [])
        recent = [t for t in times if now - t < _LOCKOUT_SEC]
        _login_log[ip] = recent
        return len([t for t in recent if now - t < _WINDOW_SEC]) >= _MAX_ATTEMPTS


def _record_fail(ip: str):
    now = time.monotonic()
    with _rate_lock:
        _login_log.setdefault(ip, []).append(now)


class User(UserMixin):
    def __init__(self, user_id):
        self.id = user_id


@dashboard_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    ip = (request.headers.get('X-Forwarded-For', request.remote_addr) or '').split(',')[0].strip()

    if request.method == 'POST':
        # Rate limit check
        if _is_locked_out(ip):
            flash('Too many failed attempts — try again in 15 minutes.', 'danger')
            return render_template('login.html', csrf_token=session.get('csrf_token', '')), 429

        # CSRF check
        if not secrets.compare_digest(
            request.form.get('csrf_token', ''),
            session.get('csrf_token', '_')
        ):
            flash('Invalid request — please reload and try again.', 'danger')
            return render_template('login.html', csrf_token=session.get('csrf_token', '')), 400

        cfg = get_config()
        username_ok = secrets.compare_digest(
            request.form.get('username', ''), cfg['auth']['username']
        )
        password_ok = secrets.compare_digest(
            request.form.get('password', ''), cfg['auth']['password']
        )
        if username_ok and password_ok:
            login_user(User(cfg['auth']['username']), remember=True)
            session.pop('csrf_token', None)
            return redirect(request.args.get('next') or url_for('dashboard.index'))

        _record_fail(ip)
        flash('Invalid credentials', 'danger')

    # Generate fresh CSRF token for every GET (and after failed POST)
    session['csrf_token'] = secrets.token_hex(32)
    return render_template('login.html', csrf_token=session['csrf_token'])


@dashboard_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('dashboard.login'))


@dashboard_bp.route('/')
@login_required
def index():
    return render_template('dashboard.html',
                            stats=get_dashboard_stats(),
                            recent_events=get_recent_events(limit=15)[0],
                            top_attackers=get_top_attackers(limit=5))


@dashboard_bp.route('/events')
@login_required
def events():
    page = max(1, int(request.args.get('page', 1)))
    per_page = min(100, int(request.args.get('per_page', 50)))
    event_type = request.args.get('type') or None
    severity = request.args.get('severity') or None
    ip = request.args.get('ip') or None

    rows, total = get_recent_events(
        limit=per_page, offset=(page - 1) * per_page,
        event_type=event_type, severity=severity, ip=ip
    )
    return render_template('events.html',
                            events=rows, total=total,
                            page=page, per_page=per_page,
                            total_pages=max(1, (total + per_page - 1) // per_page),
                            event_type=event_type, severity=severity, ip=ip)


@dashboard_bp.route('/attackers')
@login_required
def attackers():
    return render_template('attackers.html',
                            attackers=get_top_attackers(limit=200))


@dashboard_bp.route('/attacker/<path:ip>')
@login_required
def attacker_detail(ip):
    attacker = get_attacker(ip)
    if not attacker:
        flash(f'No data for IP {ip}', 'warning')
        return redirect(url_for('dashboard.attackers'))
    events_list, _ = get_recent_events(limit=100, ip=ip)
    hits, _ = get_honeypot_hits(limit=30, ip=ip)
    return render_template('attacker_detail.html',
                            attacker=attacker,
                            events=events_list,
                            honeypot_hits=hits)


@dashboard_bp.route('/honeypot')
@login_required
def honeypot():
    hits, total = get_honeypot_hits(limit=100)
    stats = get_honeypot_stats()
    cfg = get_config()
    return render_template('honeypot.html',
                            hits=hits, total=total,
                            hp_stats=stats, config=cfg)


@dashboard_bp.route('/integrity')
@login_required
def integrity():
    return render_template('integrity.html',
                            files=get_file_integrity_status())


@dashboard_bp.route('/ports')
@login_required
def ports():
    all_ports = get_all_ports()
    open_ports  = [p for p in all_ports if p['status'] == 'OPEN']
    closed_ports = [p for p in all_ports if p['status'] == 'CLOSED']
    return render_template('ports.html',
                            open_ports=open_ports,
                            closed_ports=closed_ports,
                            config=get_config())


@dashboard_bp.route('/events/ack/<int:event_id>', methods=['POST'])
@login_required
def ack_event(event_id):
    acknowledge_event(event_id)
    return redirect(request.referrer or url_for('dashboard.events'))


@dashboard_bp.route('/reset', methods=['GET', 'POST'])
@login_required
def reset_data():
    if request.method == 'POST':
        token_ok = secrets.compare_digest(
            request.form.get('csrf_token', ''),
            session.get('csrf_token', '_')
        )
        confirm_ok = request.form.get('confirm', '').strip().upper() == 'RESET'
        if token_ok and confirm_ok:
            reset_database()
            flash('All data has been reset.', 'success')
            return redirect(url_for('dashboard.index'))
        flash('Type RESET in the confirmation box to proceed.', 'danger')

    session['csrf_token'] = secrets.token_hex(32)
    return render_template('reset.html',
                            csrf_token=session['csrf_token'],
                            counts=get_record_counts())
