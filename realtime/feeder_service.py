import os, time, random, threading, logging
from logging.handlers import RotatingFileHandler
from datetime import datetime

import requests
import pandas as pd
from django.conf import settings

import dataset_generator_3

# Configuration
FEED_INTERVAL   = getattr(settings, 'FEED_INTERVAL', 10)
TEST_ENDPOINT   = getattr(settings, 'TEST_ENDPOINT', 'http://localhost:8000/realtime/api/session/')
BASE_DIR        = settings.BASE_DIR
PROFILES_CSV    = os.path.join(BASE_DIR, 'User_Profiles_Dataset.csv')
COMPANY_MAC_CSV = os.path.join(BASE_DIR, 'Company_MAC_List.csv')
LOG_FILE        = os.path.join(BASE_DIR, 'realtime_feeder.log')

# Load static data
profiles_df      = pd.read_csv(PROFILES_CSV)
company_mac_set  = set(pd.read_csv(COMPANY_MAC_CSV)['MACAddress'].tolist())
OTX_KEY          = getattr(dataset_generator_3, 'OTX_API_KEY', None)

# Logging setup
logger = logging.getLogger('realtime_feeder')
handler = RotatingFileHandler(LOG_FILE, maxBytes=5*1024*1024, backupCount=2)
handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# State
current_user_id = None
batch = []
batch_idx = 0
history = []
last_payload = {}  # Persist last IP/MAC per user for “normal” reuse
lock = threading.Lock()

def init_batch():
    global batch, batch_idx
    batch = ['ip']*2 + ['mac']*1 + ['normal']*7
    random.shuffle(batch)
    batch_idx = 0

init_batch()

def generate_payload():
    """Generate one session payload for current_user_id, injecting anomalies only as specified."""
    global batch_idx
    uid = current_user_id
    if uid is None:
        return None

    # Generate fresh metrics
    df = dataset_generator_3.generate_sessions(
        1,
        profiles_df[profiles_df['UserID'] == uid],
        company_mac_set,
        OTX_KEY
    )
    payload = df.to_dict(orient='records')[0]

    # Determine anomaly type
    typ = batch[batch_idx]
    batch_idx += 1
    if batch_idx >= len(batch):
        init_batch()

    prev = last_payload.get(uid)
    if prev is None:
        new_ip  = payload['IPAddress']
        new_mac = payload['MACAddress']
    else:
        if typ == 'normal':
            new_ip, new_mac = prev['IPAddress'], prev['MACAddress']
        elif typ == 'ip':
            parts = prev['IPAddress'].split('.')
            parts[-1] = str(random.randint(1, 254))
            new_ip  = '.'.join(parts)
            new_mac = prev['MACAddress']
        else:  # mac
            choices = list(company_mac_set - {prev['MACAddress']})
            new_mac = random.choice(choices) if choices else prev['MACAddress']
            new_ip  = prev['IPAddress']

    payload['IPAddress']  = new_ip
    payload['MACAddress'] = new_mac
    last_payload[uid]     = {'IPAddress': new_ip, 'MACAddress': new_mac}

    return payload

def post_with_retries(payload):
    backoff = 1
    for attempt in range(3):
        try:
            resp = requests.post(TEST_ENDPOINT, json=payload, timeout=5)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.warning(f'Attempt {attempt+1} failed: {e}')
            time.sleep(backoff)
            backoff *= 2
    logger.error('Failed after 3 retries')
    return None

def feed_loop():
    while True:
        with lock:
            payload = generate_payload()
        if payload:
            ts = datetime.utcnow().isoformat()
            resp = post_with_retries(payload)
            entry = {'timestamp': ts, 'payload': payload, 'response': resp}
            with lock:
                history.append(entry)
                if len(history) > 15:
                    history.pop(0)
            logger.info(f'Emitted: {payload}')
            logger.info(f'Response: {resp}')
        time.sleep(FEED_INTERVAL)

def start_feeder():
    t = threading.Thread(target=feed_loop, daemon=True)
    t.start()

# Control functions for views
def set_current_user(uid):
    global current_user_id, history
    with lock:
        current_user_id = uid
        init_batch()
        history.clear()

def get_latest_entry():
    with lock:
        return history[-1] if history else None

def get_history():
    with lock:
        return list(history)
