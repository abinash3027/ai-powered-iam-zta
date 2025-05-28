import os
import pandas as pd
import numpy as np
import re
import joblib
import tensorflow as tf
from tensorflow.keras import layers, Model
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.metrics import precision_score, recall_score, f1_score

# 0. GPU memory growth (optional)
for dev in tf.config.list_physical_devices('GPU'):
    tf.config.experimental.set_memory_growth(dev, True)

# Ensure models directory exists
models_dir = 'models'
os.makedirs(models_dir, exist_ok=True)

# 1. Load datasets
df = pd.read_csv('Dataset.csv', parse_dates=['LoginTimestamp','LogoutTimestamp'])
company_macs = pd.read_csv('Company_MAC_List.csv')
profiles     = pd.read_csv('User_Profiles_Dataset.csv')

# 2. Drop the duplicate 'UserRole' in profiles so we keep the session-side version
profiles = profiles.drop(columns=['UserRole'])

# 3. Trusted-device flag from company list
mac_set = set(company_macs['MACAddress'].str.lower())
df['is_trusted_device'] = df['MACAddress'].str.lower().isin(mac_set).astype(int)
model_map = dict(zip(company_macs['MACAddress'], company_macs['DeviceModel']))
df['CompanyDeviceModel'] = df['MACAddress'].map(model_map).fillna('NonCompany')

# 4. Merge in user profiles
df = df.merge(profiles, on='UserID', how='left')

# 5. Primary‑device flag
df['is_primary_device'] = (df['MACAddress'] == df['RegisteredDevice']).astype(int)

# 6. Parse & derive typing-range deviations
def parse_range(r):
    lo, hi = r.split('–')
    lo_val = float(re.findall(r"[\d\.]+", lo)[0])
    hi_val = float(re.findall(r"[\d\.]+", hi)[0])
    return lo_val, hi_val

# Typing speed
df[['ts_lo','ts_hi']] = df['TypingSpeedRange'].apply(lambda x: pd.Series(parse_range(x)))
df['typing_dev'] = (df['TypingSpeed'] - (df['ts_lo']+df['ts_hi'])/2) / ((df['ts_lo']+df['ts_hi'])/2)

# Key‑hold time
df[['hold_lo','hold_hi']] = df['AvgKeyHoldTimeRange'].apply(lambda x: pd.Series(parse_range(x)))
df['hold_dev'] = (df['AvgKeyHoldTime'] - (df['hold_lo']+df['hold_hi'])/2) / ((df['hold_lo']+df['hold_hi'])/2)

# Flight time
df[['flt_lo','flt_hi']] = df['AvgFlightTimeRange'].apply(lambda x: pd.Series(parse_range(x)))
df['flight_dev'] = (df['AvgFlightTime'] - (df['flt_lo']+df['flt_hi'])/2) / ((df['flt_lo']+df['flt_hi'])/2)

# Pattern match
df[['pm_lo','pm_hi']] = df['PatternMatchRange'].apply(lambda x: pd.Series(parse_range(x)))
df['pattern_dev'] = (df['PatternMatchScore'] - (df['pm_lo']+df['pm_hi'])/2) / ((df['pm_lo']+df['pm_hi'])/2)

# 7. Time & network features
df['hour']        = df['LoginTimestamp'].dt.hour
df['dow']         = df['LoginTimestamp'].dt.dayofweek
df['is_internal'] = df['IPAddress'].str.startswith('10.').astype(int)

# 8. Boolean flags → ints
for b in ['VPN_Used','GeoVelocityFlag','ThreatIntelMatch']:
    df[b] = df[b].astype(int)

# 9. Drop pure IDs, raw ranges, timestamps & IP
df = df.drop(columns=[
    'UserID','MACAddress','RegisteredDevice',
    'TypingSpeedRange','AvgKeyHoldTimeRange',
    'AvgFlightTimeRange','PatternMatchRange',
    'LoginTimestamp','LogoutTimestamp','IPAddress'
])

# 10. Define feature groups
numeric_feats = [
    'TypingSpeed','AvgKeyHoldTime','AvgFlightTime',
    'PatternMatchScore','Keystroke_Score',
    'LoginTimeDeviation','SessionDuration','Duration_RiskScore',
    'hour','dow',
    'typing_dev','hold_dev','flight_dev','pattern_dev'
]
binary_feats = [
    'VPN_Used','GeoVelocityFlag','ThreatIntelMatch',
    'is_internal','is_trusted_device','is_primary_device'
]
cat_ohe = [
    'UserRole','OperationType','DeviceType','Browser',
    'ISP','AccessChannel','KeystrokeDynamicStatus',
    'SessionLocation','Department','JobTitle',
    'Location','CompanyDeviceModel'
]

# 11. Preprocessing pipeline
preprocessor = ColumnTransformer([
    ('num', StandardScaler(), numeric_feats),
    ('bin', 'passthrough', binary_feats),
    ('cat', OneHotEncoder(sparse_output=False, handle_unknown='ignore'), cat_ohe),
], remainder='drop')

X_all = preprocessor.fit_transform(df)
print(f"Feature matrix shape: {X_all.shape}")  # e.g. (10000, N)
joblib.dump(preprocessor, os.path.join(models_dir, 'preprocessor.joblib'))
print("✅ Saved preprocessor to models/preprocessor.joblib")

# 12. Labels for evaluation
if 'IsMalicious' in df:
    y = df['IsMalicious']
elif 'AccessDecision' in df:
    y = df['AccessDecision'].map({'Allow':0,'Deny':1})
else:
    y = None

# 13. Isolation Forest
if_model = IsolationForest(
    n_estimators=200, max_samples='auto',
    contamination=0.05, random_state=42, n_jobs=-1
)
X_if_train = X_all[y==0] if y is not None else X_all
if_model.fit(X_if_train)

if y is not None:
    preds_if = if_model.predict(X_all)
    y_if    = np.where(preds_if==-1,1,0)
    print("IF →",
          f"Precision: {precision_score(y,y_if):.3f},",
          f"Recall: {recall_score(y,y_if):.3f},",
          f"F1: {f1_score(y,y_if):.3f}")

# Save Isolation Forest model
joblib.dump(if_model, os.path.join(models_dir, 'if_model.joblib'))
print("✅ Saved Isolation Forest to models/if_model.joblib")

# 14. Variational Autoencoder via subclassing
latent_dim  = 16
original_dim = X_all.shape[1]
kl_weight   = 1.25

class Encoder(Model):
    def __init__(self):
        super().__init__()
        self.d1      = layers.Dense(128, activation='relu')
        self.bn1     = layers.BatchNormalization()
        self.d2      = layers.Dense(64, activation='relu')
        self.mean    = layers.Dense(latent_dim)
        self.log_var = layers.Dense(latent_dim)
    def call(self, x):
        h   = self.d1(x); h   = self.bn1(h); h   = self.d2(h)
        m   = self.mean(h); lv  = self.log_var(h)
        eps = tf.random.normal(tf.shape(m))
        return m, lv, m + tf.exp(0.5*lv)*eps

class Decoder(Model):
    def __init__(self):
        super().__init__()
        self.d1  = layers.Dense(64, activation='relu')
        self.bn1 = layers.BatchNormalization()
        self.d2  = layers.Dense(128,activation='relu')
        self.out = layers.Dense(original_dim)
    def call(self, z):
        h = self.d1(z); h = self.bn1(h); h = self.d2(h)
        return self.out(h)

class VAE(Model):
    def __init__(self, enc, dec):
        super().__init__()
        self.enc = enc; self.dec = dec
    def compile(self, opt):
        super().compile()
        self.opt = opt
    def train_step(self, data):
        x = data[0] if isinstance(data,tuple) else data
        with tf.GradientTape() as tape:
            m, lv, z = self.enc(x)
            rec      = self.dec(z)
            rec_loss = tf.reduce_mean(tf.square(x-rec))
            kl       = -0.5*tf.reduce_mean(1+lv-tf.square(m)-tf.exp(lv))
            loss     = rec_loss + kl_weight*kl
        grads = tape.gradient(loss, self.trainable_variables)
        self.opt.apply_gradients(zip(grads,self.trainable_variables))
        return {'loss':loss, 'recon_loss':rec_loss, 'kl_loss':kl}

# Instantiate & compile VAE
encoder = Encoder()
decoder = Decoder()
vae     = VAE(encoder, decoder)
vae.compile(opt=tf.keras.optimizers.Adam())

# 15. Train/Test split & callbacks
X_tr, X_te = train_test_split(X_all, test_size=0.2, random_state=42)
callbacks = [
    tf.keras.callbacks.EarlyStopping(monitor='loss', patience=10, restore_best_weights=True),
    tf.keras.callbacks.ModelCheckpoint(
        os.path.join(models_dir, 'vae_final.weights.h5'), monitor='loss',
        save_best_only=True, save_weights_only=True
    )
]
vae.fit(X_tr, epochs=100, batch_size=128, callbacks=callbacks)

# 16. VAE scoring & eval
m, lv, zf = vae.enc(X_all)
rec_all   = vae.dec(zf)
mse       = np.mean(np.square(X_all - rec_all.numpy()), axis=1)
thr       = np.percentile(mse, 97.5)
print("Computed MSE threshold:", thr)
y_vae     = mse > thr

if y is not None:
    print("VAE →",
          f"Precision: {precision_score(y,y_vae):.3f},",
          f"Recall: {recall_score(y,y_vae):.3f},",
          f"F1: {f1_score(y,y_vae):.3f}")

# 17. Save models
vae.save_weights(os.path.join(models_dir, 'vae_final.weights.h5'))
joblib.dump(thr, os.path.join(models_dir, "mse_threshold.joblib"))
print("✅ All done. Models saved in models/")
