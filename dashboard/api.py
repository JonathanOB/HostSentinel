import threading
from flask import Blueprint, jsonify, request
from flask_login import login_required

from utils.db import (get_recent_events, get_dashboard_stats, get_events_chart_data,
                      get_top_attackers, get_honeypot_hits, get_attacker,
                      get_honeypot_stats, get_all_ports, get_file_integrity_status)

api_bp = Blueprint('api', __name__)


@api_bp.route('/stats')
@login_required
def stats():
    return jsonify(get_dashboard_stats())


@api_bp.route('/events')
@login_required
def events():
    limit = min(int(request.args.get('limit', 50)), 500)
    offset = int(request.args.get('offset', 0))
    rows, total = get_recent_events(
        limit=limit, offset=offset,
        event_type=request.args.get('type') or None,
        severity=request.args.get('severity') or None,
        ip=request.args.get('ip') or None,
    )
    return jsonify({'events': rows, 'total': total})


@api_bp.route('/chart')
@login_required
def chart():
    hours = min(int(request.args.get('hours', 24)), 168)
    return jsonify(get_events_chart_data(hours))


@api_bp.route('/attackers')
@login_required
def attackers():
    limit = min(int(request.args.get('limit', 20)), 200)
    return jsonify(get_top_attackers(limit))


@api_bp.route('/attacker/<path:ip>')
@login_required
def attacker(ip):
    data = get_attacker(ip)
    if not data:
        return jsonify({'error': 'not found'}), 404
    events, _ = get_recent_events(limit=100, ip=ip)
    hits, _ = get_honeypot_hits(limit=50, ip=ip)
    return jsonify({'attacker': data, 'events': events, 'honeypot_hits': hits})


@api_bp.route('/honeypot')
@login_required
def honeypot():
    limit = min(int(request.args.get('limit', 100)), 500)
    hits, total = get_honeypot_hits(limit=limit)
    hp_stats = get_honeypot_stats()
    return jsonify({'hits': hits, 'total': total, 'stats': hp_stats})


@api_bp.route('/ports')
@login_required
def ports():
    return jsonify(get_all_ports())


@api_bp.route('/integrity')
@login_required
def integrity():
    return jsonify(get_file_integrity_status())


@api_bp.route('/status')
@login_required
def status():
    thread_names = {t.name for t in threading.enumerate()}
    return jsonify({
        'auth_monitor':    'auth-monitor'    in thread_names,
        'file_integrity':  'file-integrity'  in thread_names,
        'ssh_honeypot':    'ssh-honeypot'    in thread_names,
        'port_monitor':    'port-monitor'    in thread_names,
    })
