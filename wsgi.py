"""
WSGI entry point for production (gunicorn).

Run with:
    gunicorn --workers 1 --threads 8 --bind 0.0.0.0:5000 wsgi:app

Single worker is required — all monitoring threads share the in-process
event_queue that drives the SSE live feed.  Use --threads to handle
concurrent HTTP requests within that worker.
"""
import threading  # needed for threading.Event()
from app import create_app
from config import get_config

app = create_app()
_config = get_config()
_stop = threading.Event()

from utils.monitor import start_monitoring
start_monitoring(_config, _stop, app.event_queue)

if _config['honeypot']['enabled']:
    from utils.honeypot import start_honeypots
    start_honeypots(_config, _stop, app.event_queue)
