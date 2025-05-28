# realtime/test_model2.py

import os
import json
import joblib
import numpy as np
import pandas as pd
import tensorflow as tf
import re
import random
from pathlib import Path
from tensorflow.keras import layers, Model
from datetime import datetime

# ─── Paths ─────────────────────────────────────────────────────────────────────
ROOT_DIR     = Path(__file__).resolve().parent.parent
MODELS_DIR   = ROOT_DIR / 'models'
STATE_FILE   = ROOT_DIR / 'last_seen.json'
HISTORY_FILE = ROOT_DIR / 'sessions_history.json'

# ─── Defaults & Helpers ────────────────────────────────────────────────────────
DEFAULT_PATTERN_MIN = 0.8
DEFAULT_PATTERN_MAX = 1.0

def parse_range(cell, dmin=None, dmax=None):
    if not isinstance(cell, str) or ('–' not in cell and '-' not in cell):
        return dmin, dmax
    lo_str, hi_str = re.split(r'–|-', cell)
    lo = float(re.findall(r"[\d\.]+", lo_str)[0])
    hi = float(re.findall(r"[\d\.]+", hi_str)[0])
    return lo, hi

def generate_metric_value(lo, hi):
    if lo is None or hi is None:
        lo, hi = DEFAULT_PATTERN_MIN, DEFAULT_PATTERN_MAX
    return random.uniform(lo, hi)

# ─── Load artifacts ────────────────────────────────────────────────────────────
preprocessor = joblib.load(MODELS_DIR / 'preprocessor.joblib')
if_model     = joblib.load(MODELS_DIR / 'if_model.joblib')
mse_thr      = joblib.load(MODELS_DIR / 'mse_threshold.joblib')

profiles_df  = pd.read_csv(ROOT_DIR / 'User_Profiles_Dataset.csv')
company_macs = pd.read_csv(ROOT_DIR / 'Company_MAC_List.csv')
trusted_set  = set(company_macs['MACAddress'].str.lower())
model_map    = dict(zip(company_macs['MACAddress'], company_macs['DeviceModel']))

# ─── VAE definition & load ─────────────────────────────────────────────────────
class Encoder(Model):
    def __init__(self, latent_dim=16):
        super().__init__()
        self.d1 = layers.Dense(128, activation='relu')
        self.bn1 = layers.BatchNormalization()
        self.d2 = layers.Dense(64, activation='relu')
        self.mean = layers.Dense(latent_dim)
        self.log_var = layers.Dense(latent_dim)
    def call(self, x):
        h   = self.d1(x); h = self.bn1(h); h = self.d2(h)
        m   = self.mean(h); lv = self.log_var(h)
        eps = tf.random.normal(tf.shape(m))
        return m, lv, m + tf.exp(0.5*lv)*eps

class Decoder(Model):
    def __init__(self, original_dim):
        super().__init__()
        self.d1  = layers.Dense(64, activation='relu')
        self.bn1 = layers.BatchNormalization()
        self.d2  = layers.Dense(128, activation='relu')
        self.out = layers.Dense(original_dim)
    def call(self, z):
        h = self.d1(z); h = self.bn1(h); h = self.d2(h)
        return self.out(h)

class VAE(Model):
    def __init__(self, enc, dec, kl_weight=1.25):
        super().__init__()
        self.enc, self.dec, self.kl_weight = enc, dec, kl_weight
    def compile(self, opt):
        super().compile()
        self.opt = opt

orig_dim = if_model.n_features_in_
encoder  = Encoder(latent_dim=16)
decoder  = Decoder(original_dim=orig_dim)
vae      = VAE(encoder, decoder)
vae.load_weights(MODELS_DIR / 'vae_final.weights.h5')
vae.compile(tf.keras.optimizers.Adam())

# ─── Persistent state ──────────────────────────────────────────────────────────
try:
    with open(STATE_FILE) as f:
        last_seen = json.load(f)
        for u, d in last_seen.items():
            d['LastLogin'] = datetime.fromisoformat(d['LastLogin'])
except FileNotFoundError:
    last_seen = {}

try:
    with open(HISTORY_FILE) as f:
        session_history = json.load(f)
except FileNotFoundError:
    session_history = {}

def _save_state():
    out = {
      u: {
        'IPAddress':  v['IPAddress'],
        'MACAddress': v['MACAddress'],
        'LastLogin':  v['LastLogin'].isoformat()
      } for u, v in last_seen.items()
    }
    with open(STATE_FILE, 'w') as f:
        json.dump(out, f)

def _save_history():
    with open(HISTORY_FILE, 'w') as f:
        json.dump(session_history, f, indent=2)

def _zero_trust_override(raw):
    uid  = str(raw['UserID'])
    prev = last_seen.get(uid)
    if prev:
        if raw['IPAddress'] != prev['IPAddress']:
            return True, f"IP changed {prev['IPAddress']} → {raw['IPAddress']}"
        if raw['MACAddress']  != prev['MACAddress']:
            return True, f"MAC changed {prev['MACAddress']} → {raw['MACAddress']}"
    return False, None

# ─── Main entrypoint ───────────────────────────────────────────────────────────
def process_entry(raw):
    # 1) Cast inputs
    raw['UserID']         = int(raw['UserID'])
    raw['TypingSpeed']    = float(raw['TypingSpeed'])
    raw['AvgKeyHoldTime'] = float(raw['AvgKeyHoldTime'])
    raw['AvgFlightTime']  = float(raw['AvgFlightTime'])

    # 2) Parse timestamps
    for k in ('LoginTimestamp','LogoutTimestamp'):
        v = raw[k]
        if isinstance(v, str) and len(v) == 16:
            v = v + ':00'
        raw[k] = datetime.fromisoformat(v) if isinstance(v, str) else v

    # 3) Profile lookup
    prof_df = profiles_df[profiles_df['UserID'] == raw['UserID']]
    if prof_df.empty:
        raise KeyError(f"No profile for UserID {raw['UserID']}")
    prof = prof_df.iloc[0]

    # 4) Static profile fields
    raw['RegisteredDevice'] = prof['RegisteredDevice']
    raw['Location']         = prof['Location']
    raw['UserRole']         = prof['UserRole']
    raw['Department']       = prof['Department']
    raw['JobTitle']         = prof['JobTitle']

    # 5) Login time deviation
    lh = raw['LoginTimestamp'].hour + raw['LoginTimestamp'].minute/60.0
    raw['LoginTimeDeviation'] = abs(lh - 12)/12

    # 6) PatternMatchScore
    pr = prof.get('PatternMatchRange', f"{DEFAULT_PATTERN_MIN}-{DEFAULT_PATTERN_MAX}")
    lo, hi = parse_range(pr, DEFAULT_PATTERN_MIN, DEFAULT_PATTERN_MAX)
    raw['PatternMatchScore'] = generate_metric_value(lo, hi)

    # 7) Derive dynamic features (typing_dev, hold_dev, etc.)
    raw['SessionDuration'] = (raw['LogoutTimestamp'] - raw['LoginTimestamp']).total_seconds()/60.0
    for col, dev in [
        ('TypingSpeedRange','typing_dev'),
        ('AvgKeyHoldTimeRange','hold_dev'),
        ('AvgFlightTimeRange','flight_dev'),
        ('PatternMatchRange','pattern_dev')
    ]:
        lo2, hi2 = parse_range(prof[col], None, None)
        val = raw['PatternMatchScore'] if col=='PatternMatchRange' else raw[col.replace('Range','')]
        raw[dev] = (val - (lo2+hi2)/2) / ((lo2+hi2)/2)

    all_ok = all(raw[d] <= 0 for d in ['typing_dev','hold_dev','flight_dev','pattern_dev'])
    raw['KeystrokeDynamicStatus'] = 'Pass' if all_ok else 'Fail'
    raw['Keystroke_Score']        = 0.0 if all_ok else 0.2

    sd = raw['SessionDuration']
    raw['Duration_RiskScore'] = (
        0.2 if sd<10 or sd>150 else
        0.1 if sd<15 or sd>120  else
        0.0
    )

    prev = last_seen.get(str(raw['UserID']), {}).get('LastLogin')
    raw['GeoVelocityFlag'] = int(
        bool(prev) and
        (raw['LoginTimestamp'] - prev).total_seconds()/60 < 120 and
        raw['SessionLocation'] != prof['Location']
    )
    raw['ThreatIntelMatch'] = 0

    # 8) Network & device flags
    ip = raw['IPAddress']
    raw['is_internal']       = int(ip.startswith('10.'))
    raw['VPN_Used']          = int(ip.startswith('100.') or ip.startswith('172.16.'))
    raw['AccessChannel']     = 'InternalNetwork' if raw['is_internal'] else 'ExternalNetwork'
    raw['ISP']               = 'CompanyISP' if raw['is_internal'] else 'PublicISP'
    raw['is_trusted_device'] = int(raw['MACAddress'].lower() in trusted_set)
    raw['CompanyDeviceModel']= model_map.get(raw['MACAddress'], 'NonCompany')
    raw['is_primary_device'] = int(raw['MACAddress'] == prof['RegisteredDevice'])
    raw['hour']              = raw['LoginTimestamp'].hour
    raw['dow']               = raw['LoginTimestamp'].weekday()

    # 9) Anomaly detection
    X     = preprocessor.transform(pd.DataFrame([raw]))
    if_p  = if_model.predict(X)[0]
    m, lv, z = vae.enc(X)
    rec_vec  = vae.dec(z)
    mse     = float(np.mean((X - rec_vec.numpy())**2, axis=1)[0])
    fflag   = 1 if if_p==-1 else 0
    vflag   = 1 if mse>mse_thr else 0
    risk_score = (fflag + vflag)/2.0
    unified    = "Low" if risk_score==0 else "High"

    # 10) Zero-Trust override flag
    ov, reason = _zero_trust_override(raw)
    if ov:
        unified    = "High"
        risk_score = 1.0

    # 11) Update last_seen
    uid = str(raw['UserID'])
    last_seen[uid] = {
      'IPAddress': raw['IPAddress'],
      'MACAddress': raw['MACAddress'],
      'LastLogin': raw['LoginTimestamp']
    }
    _save_state()

    # 12) Record history (keep last 15)
    rec = {
      "timestamp":     raw['LoginTimestamp'].isoformat(),
      "UserID":        raw['UserID'],
      "IPAddress":     raw['IPAddress'],
      "override":      ov,
      "reason":        reason if ov else "",
      "if_decision":   "Deny" if if_p==-1 else "Allow",
      "vae_decision":  "Deny" if mse>mse_thr else "Allow",
      "mse":           mse,
      "risk_score":    risk_score,
      "unified":       unified
    }
    session_history.setdefault(uid, []).append(rec)
    session_history[uid] = session_history[uid][-15:]
    _save_history()

    # 13) Return combined result
    return {
      "override":     ov,
      "reason":       reason if ov else "",
      "if_decision":  rec["if_decision"],
      "vae_decision": rec["vae_decision"],
      "mse":          rec["mse"],
      "risk_score":   rec["risk_score"],
      "unified":      rec["unified"],
      "history":      session_history[uid]
    }
save_history = _save_history