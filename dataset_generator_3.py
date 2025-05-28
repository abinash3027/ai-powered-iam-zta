#!/usr/bin/env python3
import pandas as pd
import random
import requests
from datetime import datetime, timedelta

# -------------------------------
# Configuration
# -------------------------------
NUM_SESSIONS = 50000  # Number of session logs to generate
PROFILES_CSV = "User_Profiles_Dataset.csv"  # CSV with columns: UserID, Department, UserRole, JobTitle, Location, RegisteredDevice, TypingSpeedRange, AvgKeyHoldTimeRange, AvgFlightTimeRange, PatternMatchRange
COMPANY_MAC_CSV = "Company_MAC_List.csv"  # CSV with columns: DeviceName, MACAddress, DeviceModel
OUTPUT_CSV = "IAM_Sessions_5.csv"  # Output CSV file name
OTX_API_KEY = "api_key_here"

# List of alternative locations for remote sessions
ALTERNATIVE_LOCATIONS = ["New York", "London", "Sydney", "Mumbai", "San Francisco", "Tokyo"]


# -------------------------------
# Helper Functions
# -------------------------------

def parse_range(range_str, default_min, default_max):
    """Parse a range string (e.g., "45-75") and return (min, max); if parsing fails, return defaults."""
    try:
        parts = range_str.split("-")
        if len(parts) == 2:
            return float(parts[0].strip()), float(parts[1].strip())
        else:
            return default_min, default_max
    except Exception:
        return default_min, default_max


def generate_random_mac(exclude_set=None):
    """Generate a random MAC address not present in exclude_set."""
    while True:
        mac = ":".join("{:02X}".format(random.randint(0, 255)) for _ in range(6))
        if exclude_set is None or mac not in exclude_set:
            return mac


def generate_ip(trusted, vpn_used):
    """
    Generate an IP address:
      - If trusted, return internal 10.x.x.x.
      - Otherwise, if vpn_used is True, pick an IP from 172.16.x.x or 100.x.x.x.
      - Else, return a public 192.x.x.x IP.
    """
    if trusted:
        return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    else:
        if vpn_used:
            return (f"172.16.{random.randint(0, 255)}.{random.randint(1, 254)}"
                    if random.random() < 0.5
                    else f"100.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}")
        else:
            return f"192.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def derive_isp(ip):
    """
    Determine ISP based on IP:
      - If internal (10.x.x.x or 172.16.x.x) then "CompanyISP".
      - Else, randomly choose an ISP.
    """
    if ip.startswith("10.") or ip.startswith("172.16."):
        return "CompanyISP"
    else:
        return random.choice(["Telstra", "Jio", "Verizon", "Comcast", "BT"])


def derive_access_channel(ip):
    """Return 'InternalNetwork' for internal IPs and 'ExternalNetwork' for others."""
    return "InternalNetwork" if ip.startswith("10.") or ip.startswith("172.16.") else "ExternalNetwork"


def generate_device_type():
    return random.choice(["Desktop", "Laptop", "Mobile", "Tablet"])


def generate_browser():
    return random.choice(["Chrome", "Firefox", "Edge", "Safari"])


def generate_metric_value(expected_min, expected_max, anomaly_rate=0.15, margin=0.2):
    """
    Generate a metric value:
      With high probability, returns value within expected range;
      Else, returns an anomalous value.
    """
    if random.random() > anomaly_rate:
        return random.uniform(expected_min, expected_max)
    else:
        return expected_min * (1 - margin) if random.random() < 0.5 else expected_max * (1 + margin)


def choose_operation(user_role):
    """
    Choose an OperationType based on user_role.
    Occasionally simulate role–operation mismatches.
    """
    role_operations = {
        "Admin": ["Read", "Write", "Delete", "Share"],
        "Developer": ["Read", "Write", "Share"],
        "HR": ["Read", "Write"],
        "Guest": ["Read"],
        "Finance": ["Read", "Write", "Delete", "Share"]
    }
    allowed = role_operations.get(user_role, ["Read"])
    if user_role != "Admin" and random.random() < 0.05:
        all_ops = ["Read", "Write", "Delete", "Share"]
        invalid = [op for op in all_ops if op not in allowed]
        if invalid:
            return random.choice(invalid)
    return random.choice(allowed)


def generate_login_timestamp(is_office):
    """
    Generate a login timestamp.
      - Office sessions: time between 7:00 and 10:00 AM today.
      - Remote sessions: random time within the last 24 hours.
    """
    now = datetime.now()
    if is_office:
        office_start = now.replace(hour=7, minute=0, second=0, microsecond=0)
        offset = random.randint(0, 180)
        return office_start + timedelta(minutes=offset)
    else:
        offset = random.randint(0, 1440)
        return now - timedelta(minutes=offset)


def generate_random_timestamp():
    """Generate a random timestamp within the last 24 hours (for previous login simulation)."""
    now = datetime.now()
    delta = random.randint(0, 1440)
    return now - timedelta(minutes=delta)


def check_threat_intel(ip_address, otx_api_key, threat_cache):
    """
    Query AlienVault OTX API for the given IP (only for external IPs).
    Cache the result to avoid duplicate queries.
    """
    if ip_address in threat_cache:
        return threat_cache[ip_address]
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general"
    headers = {"X-OTX-API-KEY": otx_api_key}
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            result = pulse_count > 0
        else:
            result = False
    except Exception:
        result = False
    threat_cache[ip_address] = result
    return result


def evaluate_access_decision(user_role, op_type, trusted, threat_intel, keystroke_status,
                             login_deviation, vpn_used, geo_velocity, aggregate_behavior):
    """
    Compute the final AccessDecision using all risk signals.
    Immediate Deny if:
      - Role–operation mismatch, threat intel flag, keystroke failure, or high login deviation.
    Also, if aggregate behavioral risk > 0.3.
    A VPN exception applies if geo anomaly is flagged.
    """
    valid_ops = {
        "Admin": ["Read", "Write", "Delete", "Share"],
        "Developer": ["Read", "Write", "Share"],
        "HR": ["Read", "Write"],
        "Guest": ["Read"],
        "Finance": ["Read", "Write", "Delete", "Share"]
    }
    if op_type not in valid_ops.get(user_role, []):
        return "Deny"
    if threat_intel:
        return "Deny"
    if keystroke_status == "Fail":
        return "Deny"
    if login_deviation > 0.9:
        return "Deny"
    if not trusted and random.random() < 0.1:
        return "Deny"
    if vpn_used and geo_velocity:
        return "Allow"
    if aggregate_behavior > 0.3:
        return "Deny"
    return "Allow"


# -------------------------------
# Session Generation Function
# -------------------------------
def generate_sessions(num_sessions, profiles_df, company_mac_set, otx_api_key):
    sessions = []
    threat_cache = {}

    # Default expected keystroke ranges.
    DEFAULT_TYPING_SPEED_MIN = 45
    DEFAULT_TYPING_SPEED_MAX = 75
    DEFAULT_KEY_HOLD_MIN = 80
    DEFAULT_KEY_HOLD_MAX = 150
    DEFAULT_FLIGHT_TIME_MIN = 50
    DEFAULT_FLIGHT_TIME_MAX = 120
    DEFAULT_PATTERN_MIN = 0.8
    DEFAULT_PATTERN_MAX = 1.0

    for _ in range(num_sessions):
        user = profiles_df.sample(n=1).iloc[0].to_dict()

        # Reassign "Guest" role 70% of the time.
        user_role = user.get("UserRole", "Guest")
        if user_role == "Guest" and random.random() < 0.7:
            user_role = random.choice(["Admin", "Developer", "HR", "Finance"])

        # Determine if session is office-based (60% chance).
        is_office = random.random() < 0.6
        if is_office:
            mac_address = user["RegisteredDevice"]
            trusted = True
            session_location = user.get("Location", "Unknown")
            previous_timestamp = None  # Not used for office sessions.
        else:
            mac_address = generate_random_mac(exclude_set=company_mac_set)
            trusted = False
            # Remote sessions: determine VPN usage and session location.
            if random.random() < 0.5:
                vpn_used = True
                session_location = user.get("Location", "Unknown")
            else:
                vpn_used = False
                session_location = random.choice(ALTERNATIVE_LOCATIONS) if random.random() < 0.4 else user.get(
                    "Location", "Unknown")
            previous_timestamp = generate_random_timestamp() - timedelta(minutes=random.randint(30, 240))

        op_type = choose_operation(user_role)
        device_type = generate_device_type()
        browser = generate_browser()

        # For office sessions, force vpn_used to False.
        if is_office:
            vpn_used = False

        ip_address = generate_ip(trusted, vpn_used)
        isp = derive_isp(ip_address)
        access_channel = derive_access_channel(ip_address)

        # Parse keystroke ranges.
        typing_range = user.get("TypingSpeedRange", f"{DEFAULT_TYPING_SPEED_MIN}-{DEFAULT_TYPING_SPEED_MAX}")
        key_hold_range = user.get("AvgKeyHoldTimeRange", f"{DEFAULT_KEY_HOLD_MIN}-{DEFAULT_KEY_HOLD_MAX}")
        flight_range = user.get("AvgFlightTimeRange", f"{DEFAULT_FLIGHT_TIME_MIN}-{DEFAULT_FLIGHT_TIME_MAX}")
        pattern_range = user.get("PatternMatchRange", f"{DEFAULT_PATTERN_MIN}-{DEFAULT_PATTERN_MAX}")

        typing_min, typing_max = parse_range(typing_range, DEFAULT_TYPING_SPEED_MIN, DEFAULT_TYPING_SPEED_MAX)
        key_hold_min, key_hold_max = parse_range(key_hold_range, DEFAULT_KEY_HOLD_MIN, DEFAULT_KEY_HOLD_MAX)
        flight_min, flight_max = parse_range(flight_range, DEFAULT_FLIGHT_TIME_MIN, DEFAULT_FLIGHT_TIME_MAX)
        pattern_min, pattern_max = parse_range(pattern_range, DEFAULT_PATTERN_MIN, DEFAULT_PATTERN_MAX)

        typing_speed = generate_metric_value(typing_min, typing_max)
        avg_key_hold_time = generate_metric_value(key_hold_min, key_hold_max)
        avg_flight_time = generate_metric_value(flight_min, flight_max)
        pattern_match_score = generate_metric_value(pattern_min, pattern_max)

        if (typing_min <= typing_speed <= typing_max and
                key_hold_min <= avg_key_hold_time <= key_hold_max and
                flight_min <= avg_flight_time <= flight_max and
                pattern_min <= pattern_match_score <= pattern_max):
            keystroke_status = "Pass"
        else:
            keystroke_status = "Fail"

        login_deviation = round(random.uniform(0.0, 1.0), 2)

        # Generate login timestamp using office/remote logic.
        login_timestamp = generate_login_timestamp(is_office)

        # Simulate session duration (between 10 and 120 minutes) and compute logout timestamp.
        session_duration = random.randint(10, 120)
        logout_timestamp = login_timestamp + timedelta(minutes=session_duration)
        # Evaluate Duration_RiskScore:
        if session_duration < 10 or session_duration > 150:
            Duration_RiskScore = 0.2
        elif session_duration < 15 or session_duration > 120:
            Duration_RiskScore = 0.1
        else:
            Duration_RiskScore = 0

        Keystroke_Score = 0 if keystroke_status == "Pass" else 0.2

        # Compute the Aggregate Behavioral Risk as a weighted sum.
        Aggregate_Behavior = (0.5 * Keystroke_Score) + (0.5 * Duration_RiskScore)

        if is_office:
            geo_velocity_flag = False
        else:
            if not vpn_used and previous_timestamp:
                time_diff = (login_timestamp - previous_timestamp).total_seconds() / 60
                geo_velocity_flag = (session_location != user.get("Location", "")) and (time_diff < 120)
            else:
                geo_velocity_flag = False

        if trusted:
            threat_intel = False
        else:
            if not (ip_address.startswith("10.") or ip_address.startswith("172.16.")):
                threat_intel = check_threat_intel(ip_address, otx_api_key, threat_cache)
            else:
                threat_intel = False

        access_decision = evaluate_access_decision(
            user_role=user_role,
            op_type=op_type,
            trusted=trusted,
            threat_intel=threat_intel,
            keystroke_status=keystroke_status,
            login_deviation=login_deviation,
            vpn_used=vpn_used,
            geo_velocity=geo_velocity_flag,
            aggregate_behavior=Aggregate_Behavior
        )

        # Build final session record including all calculated attributes.
        session_record = {
            "UserID": user.get("UserID", random.randint(10001, 10280)),
            "MACAddress": mac_address,
            "UserRole": user_role,
            "OperationType": op_type,
            "DeviceType": device_type,
            "Browser": browser,
            "IPAddress": ip_address,
            "VPN_Used": vpn_used,
            "ISP": isp,
            "AccessChannel": access_channel,
            "TypingSpeed": round(typing_speed, 2),
            "AvgKeyHoldTime": round(avg_key_hold_time, 2),
            "AvgFlightTime": round(avg_flight_time, 2),
            "PatternMatchScore": round(pattern_match_score, 2),
            "KeystrokeDynamicStatus": keystroke_status,
            "Keystroke_Score": Keystroke_Score,
            "LoginTimeDeviation": login_deviation,
            "LoginTimestamp": login_timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "LogoutTimestamp": logout_timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "SessionDuration": session_duration,
            "Duration_RiskScore": Duration_RiskScore,
            "Aggregate_Behavior": round(Aggregate_Behavior, 2),
            "GeoVelocityFlag": geo_velocity_flag,
            "ThreatIntelMatch": threat_intel,
            "AccessDecision": access_decision,
            "SessionLocation": session_location
        }
        sessions.append(session_record)

    # Arrange final columns in a logical order.
    columns_order = [
        "UserID",
        "MACAddress",
        "UserRole",
        "OperationType",
        "DeviceType",
        "Browser",
        "IPAddress",
        "VPN_Used",
        "ISP",
        "AccessChannel",
        "TypingSpeed",
        "AvgKeyHoldTime",
        "AvgFlightTime",
        "PatternMatchScore",
        "KeystrokeDynamicStatus",
        "Keystroke_Score",
        "LoginTimeDeviation",
        "LoginTimestamp",
        "LogoutTimestamp",
        "SessionDuration",
        "Duration_RiskScore",
        "Aggregate_Behavior",
        "GeoVelocityFlag",
        "ThreatIntelMatch",
        "AccessDecision",
        "SessionLocation"
    ]

    df = pd.DataFrame(sessions)
    return df[columns_order]


# -------------------------------
# Main Execution
# -------------------------------
def main():
    # Read and clean CSV files.
    profiles_df = pd.read_csv(PROFILES_CSV)
    profiles_df.columns = profiles_df.columns.str.strip()

    company_mac_df = pd.read_csv(COMPANY_MAC_CSV)
    company_mac_df.columns = company_mac_df.columns.str.strip()

    company_mac_set = set(company_mac_df["MACAddress"].tolist())

    sessions_df = generate_sessions(NUM_SESSIONS, profiles_df, company_mac_set, OTX_API_KEY)
    sessions_df.to_csv(OUTPUT_CSV, index=False)
    print(f"Generated {NUM_SESSIONS} session logs saved to {OUTPUT_CSV}")


if __name__ == "__main__":
    main()
