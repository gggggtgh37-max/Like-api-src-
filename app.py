from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
import threading
import urllib3
import random
import os

# ------------------ CONFIG ------------------
TOKEN_BATCH_SIZE = 189
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

API_KEY = os.environ.get("API_KEY", "drift")

# Region -> Endpoint
REGION_URL = {
    "IND": "https://client.ind.freefiremobile.com",
    "BR":  "https://client.us.freefiremobile.com",
    "US":  "https://client.us.freefiremobile.com",
    "SAC": "https://client.us.freefiremobile.com",
    "NA":  "https://client.us.freefiremobile.com",
    "BD":  "https://clientbp.ggpolarbear.com",
    "ME":  "https://clientbp.ggpolarbear.com",
    "VN":  "https://clientbp.ggpolarbear.com",
    "PK":  "https://clientbp.ggpolarbear.com",
    "SG":  "https://clientbp.ggpolarbear.com",
    "ID":  "https://clientbp.ggpolarbear.com",
    "RU":  "https://clientbp.ggpolarbear.com",
    "TH":  "https://clientbp.ggpolarbear.com",
    "TW":  "https://clientbp.ggpolarbear.com",
    "EU":  "https://clientbp.ggpolarbear.com",
}

VALID_REGIONS = set(REGION_URL.keys())

# Region code -> list of acceptable file name aliases (first = preferred)
REGION_ALIASES = {
    "IND": ["INDIA", "IND"],
    "BD":  ["BANGLADESH", "BD"],
    "BR":  ["BRAZIL", "BR"],
    "NA":  ["NORTH_AMERICA", "NORTHAMERICA", "NA"],
    "US":  ["UNITED_STATES", "UNITEDSTATES", "USA", "US"],
    "SAC": ["SOUTH_AMERICA", "SOUTHAMERICA", "SAC"],
    "ME":  ["MIDDLE_EAST", "MIDDLEEAST", "ME"],
    "VN":  ["VIETNAM", "VN"],
    "PK":  ["PAKISTAN", "PK"],
    "SG":  ["SINGAPORE", "SG"],
    "ID":  ["INDONESIA", "ID"],
    "RU":  ["RUSSIA", "RU"],
    "TH":  ["THAILAND", "TH"],
    "TW":  ["TAIWAN", "TW"],
    "EU":  ["EUROPE", "EU"],
}


def _find_token_file(server_name: str):
    """
    Case-insensitive search for the best matching token file.
    Tries: token_INDIA.json, token_IND.json (any case).
    Returns the real filename on disk, or None.
    """
    aliases = REGION_ALIASES.get(server_name, [server_name])
    try:
        files = os.listdir('.')
    except Exception:
        files = []
    lower_map = {f.lower(): f for f in files}

    for alias in aliases:
        candidate = f"token_{alias}.json"
        hit = lower_map.get(candidate.lower())
        if hit:
            return hit
    return None


def token_file_for(server_name: str) -> str:
    """
    Return real file name if found, else return preferred name (for error messages).
    """
    found = _find_token_file(server_name)
    if found:
        return found
    # preferred default name (used only in error messages)
    aliases = REGION_ALIASES.get(server_name, [server_name])
    return f"token_{aliases[0]}.json"


# Rotating pointer — keyed by region code (stable regardless of file case)
current_batch_indices = {}
batch_indices_lock = threading.Lock()


# ------------------ BATCHING ------------------
def get_next_batch_tokens(server_name, all_tokens):
    if not all_tokens:
        return []
    total = len(all_tokens)
    if total <= TOKEN_BATCH_SIZE:
        return all_tokens

    key = server_name  # use region code, not file name
    with batch_indices_lock:
        idx = current_batch_indices.get(key, 0)
        end = idx + TOKEN_BATCH_SIZE
        if end > total:
            remaining = end - total
            batch = all_tokens[idx:total] + all_tokens[0:remaining]
        else:
            batch = all_tokens[idx:end]
        current_batch_indices[key] = (idx + TOKEN_BATCH_SIZE) % total
        return batch


def get_random_batch_tokens(server_name, all_tokens):
    if not all_tokens:
        return []
    if len(all_tokens) <= TOKEN_BATCH_SIZE:
        return all_tokens.copy()
    return random.sample(all_tokens, TOKEN_BATCH_SIZE)


# ------------------ TOKEN LOADER ------------------
def load_tokens(server_name, for_visit=False):
    path = _find_token_file(server_name)
    if not path:
        print(f"Warning: no token file found for {server_name} "
              f"(expected like {token_file_for(server_name)})")
        return []

    try:
        with open(path, "r") as f:
            tokens = json.load(f)
            if isinstance(tokens, list) and all(
                isinstance(t, dict) and "token" in t for t in tokens
            ):
                print(f"Loaded {len(tokens)} tokens from {path} for {server_name}")
                return tokens
            print(f"Warning: {path} has unexpected format.")
            return []
    except json.JSONDecodeError:
        print(f"Warning: token file {path} has invalid JSON.")
        return []
    except Exception as e:
        print(f"Error reading {path}: {e}")
        return []


# ------------------ ENCRYPTION ------------------
def encrypt_message(plaintext: bytes) -> str:
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(plaintext, AES.block_size)
    return binascii.hexlify(cipher.encrypt(padded)).decode('utf-8')


# ------------------ PROTOBUF BUILDERS ------------------
def create_protobuf_message(user_id: int, region: str) -> bytes:
    message = like_pb2.like()
    message.uid = int(user_id)
    message.region = region
    return message.SerializeToString()


def create_protobuf_for_profile_check(uid: int) -> bytes:
    message = uid_generator_pb2.uid_generator()

    if hasattr(message, "id"):
        message.id = int(uid)
    elif hasattr(message, "playerId"):
        message.playerId = int(uid)
    elif hasattr(message, "krishna_"):
        message.krishna_ = int(uid)
    else:
        print("ERROR: no uid field in uid_generator_pb2.uid_generator. Fields:",
              list(message.DESCRIPTOR.fields_by_name.keys()))
        raise AttributeError("uid field not found in uid_generator_pb2.uid_generator")

    if hasattr(message, "teamXdarks"):
        message.teamXdarks = 1

    return message.SerializeToString()


def enc_profile_check_payload(uid: int) -> str:
    return encrypt_message(create_protobuf_for_profile_check(uid))


# ------------------ HTTP CALLS ------------------
async def send_single_like_request(encrypted_like_payload, token_dict, url):
    edata = bytes.fromhex(encrypted_like_payload)
    token_value = token_dict.get("token", "")
    if not token_value:
        return 999

    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Authorization': f"Bearer {token_value}",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB55",
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers,
                                    timeout=aiohttp.ClientTimeout(total=10)) as r:
                if r.status != 200:
                    print(f"Like failed ({token_value[:10]}...) status={r.status}")
                return r.status
    except asyncio.TimeoutError:
        return 998
    except Exception as e:
        print(f"Exception for {token_value[:10]}...: {e}")
        return 997


async def send_likes_with_token_batch(uid, server_region_for_like_proto,
                                      like_api_url, token_batch_to_use):
    if not token_batch_to_use:
        return []
    proto = create_protobuf_message(uid, server_region_for_like_proto)
    enc = encrypt_message(proto)
    tasks = [send_single_like_request(enc, t, like_api_url)
             for t in token_batch_to_use]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    ok = sum(1 for r in results if isinstance(r, int) and r == 200)
    print(f"Sent {len(token_batch_to_use)} likes | OK={ok} | FAIL={len(token_batch_to_use)-ok}")
    return results


def make_profile_check_request(encrypted_profile_payload, server_name, token_dict):
    token_value = token_dict.get("token", "")
    if not token_value:
        return None

    base = REGION_URL.get(server_name)
    if not base:
        print(f"Unknown region {server_name}")
        return None
    url = f"{base}/GetPlayerPersonalShow"

    edata = bytes.fromhex(encrypted_profile_payload)
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Authorization': f"Bearer {token_value}",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB55",
    }
    try:
        r = requests.post(url, data=edata, headers=headers, verify=False, timeout=10)
        r.raise_for_status()
        return decode_protobuf_profile_info(r.content)
    except requests.exceptions.HTTPError as e:
        print(f"HTTP error ({token_value[:10]}...): {e.response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Request error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
    return None


def decode_protobuf_profile_info(binary_data):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary_data)
        return items
    except Exception as e:
        print(f"Error decoding profile protobuf: {e}")
        return None


# ------------------ FLASK ------------------
app = Flask(__name__)


@app.route('/like', methods=['GET'])
def handle_requests():
    api_key = request.headers.get("X-API-KEY") or request.args.get("api_key")
    if api_key != API_KEY:
        return jsonify({"error": "Unauthorized. Invalid API key."}), 401

    uid_param = request.args.get("uid")
    server_name_param = request.args.get("server_name", "").upper().strip()
    use_random = request.args.get("random", "false").lower() == "true"

    if not uid_param or not server_name_param:
        return jsonify({"error": "UID and server_name are required"}), 400

    if server_name_param not in VALID_REGIONS:
        return jsonify({
            "error": f"Invalid server_name. Use one of: {sorted(VALID_REGIONS)}"
        }), 400

    visit_tokens = load_tokens(server_name_param, for_visit=True)
    if not visit_tokens:
        return jsonify({
            "error": f"No tokens for {server_name_param} "
                     f"(expected file like {token_file_for(server_name_param)})."
        }), 500
    visit_token = visit_tokens[0]

    all_tokens = load_tokens(server_name_param, for_visit=False)
    if not all_tokens:
        return jsonify({
            "error": f"No tokens for {server_name_param} "
                     f"(expected file like {token_file_for(server_name_param)})."
        }), 500

    real_file = _find_token_file(server_name_param) or token_file_for(server_name_param)
    print(f"[{server_name_param}] total tokens: {len(all_tokens)} (file: {real_file})")

    if use_random:
        batch = get_random_batch_tokens(server_name_param, all_tokens)
        print(f"[{server_name_param}] RANDOM batch size={len(batch)}")
    else:
        batch = get_next_batch_tokens(server_name_param, all_tokens)
        print(f"[{server_name_param}] ROTATING batch size={len(batch)}")

    enc_uid = enc_profile_check_payload(uid_param)

    before_info = make_profile_check_request(enc_uid, server_name_param, visit_token)
    before_likes = 0
    if before_info and hasattr(before_info, 'AccountInfo'):
        before_likes = int(before_info.AccountInfo.Likes)

    print(f"[{server_name_param}] UID {uid_param} likes before = {before_likes}")

    like_api_url = f"{REGION_URL[server_name_param]}/LikeProfile"

    if batch:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(
                send_likes_with_token_batch(
                    uid_param, server_name_param, like_api_url, batch
                )
            )
        finally:
            loop.close()

    after_info = make_profile_check_request(enc_uid, server_name_param, visit_token)
    after_likes = before_likes
    real_uid = int(uid_param)
    nickname = "N/A"

    if after_info and hasattr(after_info, 'AccountInfo'):
        after_likes = int(after_info.AccountInfo.Likes)
        real_uid = int(after_info.AccountInfo.UID)
        if after_info.AccountInfo.PlayerNickname:
            nickname = str(after_info.AccountInfo.PlayerNickname)

    print(f"[{server_name_param}] UID {uid_param} likes after = {after_likes}")

    delta = after_likes - before_likes
    status = 1 if delta > 0 else (2 if delta == 0 else 3)

    return jsonify({
        "LikesGivenByAPI": delta,
        "LikesafterCommand": after_likes,
        "LikesbeforeCommand": before_likes,
        "PlayerNickname": nickname,
        "UID": real_uid,
        "Region": server_name_param,
        "status": status,
        "Note": (f"visit token used for profile check; "
                 f"{'random' if use_random else 'rotating'} batch "
                 f"of {len(batch)} tokens for like send."),
        "Owner": "@DG_DRIFT",
        "Tg": "DGDRIFT",
    })


# ------------------ RESET (sirf reload, kuch delete nahi) ------------------
@app.route('/reset', methods=['GET'])
def reset_state():
    """Reload everything in memory. Token files are NOT touched."""
    secret = request.args.get("secret", "")
    if secret != "drift":
        return jsonify({"error": "Unauthorized. Invalid secret."}), 401

    with batch_indices_lock:
        current_batch_indices.clear()

    reloaded = {}
    for server in sorted(VALID_REGIONS):
        regular = load_tokens(server, for_visit=False)
        reloaded[server] = {
            "regular_tokens": len(regular),
            "token_file":     _find_token_file(server) or token_file_for(server),
        }

    return jsonify({
        "status": "ok",
        "message": "All state reloaded. Token files untouched.",
        "regions": reloaded,
        "Owner": "@DG_DRIFT",
        "Tg": "DGDRIFT",
    })


# ------------------ TOKEN INFO ------------------
@app.route('/token_info', methods=['GET'])
def token_info():
    info = {}
    for server in sorted(VALID_REGIONS):
        real = _find_token_file(server)
        info[server] = {
            "regular_tokens": len(load_tokens(server, for_visit=False)),
            "token_file":     real or token_file_for(server),
            "found":          bool(real),
            "endpoint":       REGION_URL[server],
        }
    return jsonify(info)


@app.route('/healthz', methods=['GET'])
def healthz():
    return jsonify({"ok": True, "regions": sorted(VALID_REGIONS)})


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)