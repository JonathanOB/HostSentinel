import os
import sys
import json
import queue
import signal
import logging
import threading
from flask import Flask, Response, stream_with_context
from flask_login import LoginManager

from config import get_config
from models import init_db


event_queue: queue.Queue = queue.Queue(maxsize=1000)
_monitor_threads = []
_honeypot_threads = []

from utils.db import set_event_queue as _set_event_queue
_set_event_queue(event_queue)


def create_app():
    config = get_config()

    app = Flask(
        __name__,
        template_folder='dashboard/templates',
        static_folder='dashboard/static'
    )
    app.secret_key = config['sentinel']['secret_key']
    app.config['SENTINEL_CONFIG'] = config

    log_path = config['logging']['path']
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    # On Windows the console defaults to cp1252; wrap stdout in UTF-8 so
    # log messages with non-ASCII chars don't crash the StreamHandler.
    import io as _io
    _stdout = (
        _io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace', line_buffering=True)
        if hasattr(sys.stdout, 'buffer') else sys.stdout
    )
    logging.basicConfig(
        level=getattr(logging, config['logging']['level'], logging.INFO),
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        handlers=[
            logging.FileHandler(log_path, encoding='utf-8'),
            logging.StreamHandler(_stdout),
        ]
    )

    os.makedirs(os.path.dirname(config['database']['path']), exist_ok=True)
    init_db()

    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'dashboard.login'
    login_manager.login_message_category = 'warning'

    from dashboard.routes import User

    @login_manager.user_loader
    def load_user(user_id):
        if user_id == config['auth']['username']:
            return User(user_id)
        return None

    from dashboard.routes import dashboard_bp
    from dashboard.api import api_bp
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(api_bp, url_prefix='/api')

    if config['honeypot']['enabled'] and config['honeypot']['http']['enabled']:
        from utils.honeypot import build_http_traps
        for path, view_func in build_http_traps(config, event_queue):
            app.add_url_rule(path, view_func=view_func, methods=['GET', 'POST'])

    @app.route('/stream')
    def stream():
        def generate():
            while True:
                try:
                    evt = event_queue.get(timeout=1)
                    yield f"data: {json.dumps(evt)}\n\n"
                except queue.Empty:
                    yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
        return Response(
            stream_with_context(generate()),
            mimetype='text/event-stream',
            headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
        )

    @app.template_filter('filesizeformat')
    def _filesizeformat(n):
        if not n:
            return '0 B'
        for unit in ('B', 'KB', 'MB', 'GB'):
            if n < 1024:
                return f"{int(n)} {unit}"
            n /= 1024
        return f"{n:.1f} TB"

    _WELL_KNOWN_PORTS = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
        993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL',
        3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
        8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 8888: 'Jupyter', 27017: 'MongoDB',
    }

    @app.template_filter('service_name')
    def _service_name(port):
        return _WELL_KNOWN_PORTS.get(port, 'Unknown')

    app.event_queue = event_queue
    return app


def main():
    app = create_app()
    config = get_config()
    stop_event = threading.Event()

    from utils.monitor import start_monitoring
    _monitor_threads.extend(start_monitoring(config, stop_event, event_queue))

    if config['honeypot']['enabled']:
        from utils.honeypot import start_honeypots
        _honeypot_threads.extend(start_honeypots(config, stop_event, event_queue))

    if config.get('port_monitor', {}).get('enabled', True):
        from utils.port_monitor import start_port_monitor
        _monitor_threads.append(start_port_monitor(config, stop_event))

    host = config['sentinel']['host']
    port = config['sentinel']['port']
    logging.info(f"HostSentinel starting on {host}:{port}")

    try:
        from waitress import serve
        logging.info("Server: waitress (32 threads)")
        serve(app, host=host, port=port, threads=32, channel_timeout=3600)
    except ImportError:
        def _shutdown(sig, frame):
            logging.info("Shutting down HostSentinel...")
            stop_event.set()
            sys.exit(0)
        signal.signal(signal.SIGINT, _shutdown)
        signal.signal(signal.SIGTERM, _shutdown)
        app.run(host=host, port=port, debug=config['sentinel']['debug'],
                threaded=True, use_reloader=False)


if __name__ == '__main__':
    main()
