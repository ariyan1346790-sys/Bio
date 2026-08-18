import os
import re
import urllib.parse
import urllib3
import requests
from datetime import datetime
from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =============================================================================
# 🔐 ইন-মেমোরি প্রোটোবাফ বিল্ডার
# =============================================================================
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder

_sym_db = _symbol_database.Default()

DESCRIPTOR_REQ = _descriptor_pool.Default().AddSerializedFile(
    b'\n\x13MajorLoginReq.proto\"\xfa\n\n\nMajorLogin\x12\x12\n\nevent_time\x18\x03 \x01(\t\x12\x11\n\tgame_name\x18\x04 \x01(\t\x12\x13\n\x0b\x70latform_id\x18\x05 \x01(\x05\x12\x16\n\x0e\x63lient_version\x18\x07 \x01(\t\x12\x17\n\x0fsystem_software\x18\x08 \x01(\t\x12\x17\n\x0fsystem_hardware\x18\t \x01(\t\x12\x18\n\x10telecom_operator\x18\n \x01(\t\x12\x14\n\x0cnetwork_type\x18\x0b \x01(\t\x12\x14\n\x0cscreen_width\x18\x0c \x01(\r\x12\x15\n\rscreen_height\x18\r \x01(\r\x12\x12\n\nscreen_dpi\x18\x0e \x01(\t\x12\x19\n\x11processor_details\x18\x0f \x01(\t\x12\x0e\n\x06memory\x18\x10 \x01(\r\x12\x14\n\x0cgpu_renderer\x18\x11 \x01(\t\x12\x13\n\x0bgpu_version\x18\x12 \x01(\t\x12\x18\n\x10unique_device_id\x18\x13 \x01(\t\x12\x11\n\tclient_ip\x18\x14 \x01(\t\x12\x10\n\x08language\x18\x15 \x01(\t\x12\x0f\n\x07open_id\x18\x16 \x01(\t\x12\x14\n\x0copen_id_type\x18\x17 \x01(\t\x12\x13\n\x0b\x64\x65vice_type\x18\x18 \x01(\t\x12\'\n\x10memory_available\x18\x19 \x01(\x0b\x32\r.GameSecurity\x12\x14\n\x0c\x61\x63\x63\x65ss_token\x18\x1d \x01(\t\x12\x17\n\x0fplatform_sdk_id\x18\x1e \x01(\x05\x12\x1a\n\x12network_operator_a\x18) \x01(\t\x12\x16\n\x0enetwork_type_a\x18* \x01(\t\x12\x1c\n\x14\x63lient_using_version\x18\x39 \x01(\t\x12\x1e\n\x16\x65xternal_storage_total\x18< \x01(\x05\x12\"\n\x1a\x65xternal_storage_available\x18= \x01(\x05\x12\x1e\n\x16internal_storage_total\x18> \x01(\x05\x12\"\n\x1ainternal_storage_available\x18? \x01(\x05\x12#\n\x1bgame_disk_storage_available\x18@ \x01(\x05\x12\x1f\n\x17game_disk_storage_total\x18\x41 \x01(\x05\x12%\n\x1d\x65xternal_sdcard_avail_storage\x18\x42 \x01(\x05\x12%\n\x1d\x65xternal_sdcard_total_storage\x18\x43 \x01(\x05\x12\x10\n\x08login_by\x18I \x01(\x05\x12\x14\n\x0clibrary_path\x18J \x01(\t\x12\x12\n\nreg_avatar\x18L \x01(\x05\x12\x15\n\rlibrary_token\x18M \x01(\t\x12\x14\n\x0c\x63hannel_type\x18N \x01(\x05\x12\x10\n\x08\x63pu_type\x18O \x01(\x05\x12\x18\n\x10\x63pu_architecture\x18Q \x01(\t\x12\x1b\n\x13\x63lient_version_code\x18S \x01(\t\x12\x14\n\x0cgraphics_api\x18V \x01(\t\x12\x1d\n\x15supported_astc_bitset\x18W \x01(\r\x12\x1a\n\x12login_open_id_type\x18X \x01(\x05\x12\x18\n\x10\x61nalytics_detail\x18Y \x01(\x0c\x12\x14\n\x0cloading_time\x18\\ \x01(\r\x12\x17\n\x0frelease_channel\x18] \x01(\t\x12\x12\n\nextra_info\x18^ \x01(\t\x12 \n\x18\x61ndroid_engine_init_flag\x18_ \x01(\r\x12\x0f\n\x07if_push\x18\x61 \x01(\x05\x12\x0e\n\x06is_vpn\x18\x62 \x01(\x05\x12\x1c\n\x14origin_platform_type\x18\x63 \x01(\t\x12\x1d\n\x15primary_platform_type\x18\x64 \x01(\t\"5\n\x0cGameSecurity\x12\x0f\n\x07version\x18\x06 \x01(\x05\x12\x14\n\x0chidden_value\x18\x08 \x01(\x04\x62\x06proto3'
)
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR_REQ, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR_REQ, 'MajorLoginReq_pb2', globals())

DESCRIPTOR_RES = _descriptor_pool.Default().AddSerializedFile(
    b'\n\x13MajorLoginRes.proto\"|\n\rMajorLoginRes\x12\x13\n\x0b\x61\x63\x63ount_uid\x18\x01 \x01(\x04\x12\x0e\n\x06region\x18\x02 \x01(\t\x12\r\n\x05token\x18\x08 \x01(\t\x12\x0b\n\x03url\x18\n \x01(\t\x12\x11\n\ttimestamp\x18\x15 \x01(\x03\x12\x0b\n\x03key\x18\x16 \x01(\x0c\x12\n\n\x02iv\x18\x17 \x01(\x0c\x62\x06proto3'
)
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR_RES, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR_RES, 'MajorLoginRes_pb2', globals())

DESCRIPTOR_BIO = _descriptor_pool.Default().AddSerializedFile(
    b'\n\ndata.proto\"\xbb\x01\n\x04\x44\x61ta\x12\x0f\n\x07\x66ield_2\x18\x02 \x01(\x05\x12\x1e\n\x07\x66ield_5\x18\x05 \x01(\x0b\x32\r.EmptyMessage\x12\x1e\n\x07\x66ield_6\x18\x06 \x01(\x0b\x32\r.EmptyMessage\x12\x0f\n\x07\x66ield_8\x18\x08 \x01(\t\x12\x0f\n\x07\x66ield_9\x18\t \x01(\x05\x12\x1f\n\x08\x66ield_11\x18\x0b \x01(\x0b\x32\r.EmptyMessage\x12\x1f\n\x08\x66ield_12\x18\x0c \x01(\x0b\x32\r.EmptyMessage\"\x0e\n\x0c\x45mptyMessageb\x06proto3'
)
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR_BIO, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR_BIO, 'data1_pb2', globals())

MajorLogin = _sym_db.GetSymbol('MajorLogin')
MajorLoginRes = _sym_db.GetSymbol('MajorLoginRes')
BioData = _sym_db.GetSymbol('Data')
EmptyMessage = _sym_db.GetSymbol('EmptyMessage')

STATIC_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
STATIC_IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
CLIENT_VERSION = "1.126.4"

def enc_aes(data: bytes) -> bytes:
    return AES.new(STATIC_KEY, AES.MODE_CBC, STATIC_IV).encrypt(pad(data, 16))

def dec_aes(data: bytes) -> bytes:
    try:
        return unpad(AES.new(STATIC_KEY, AES.MODE_CBC, STATIC_IV).decrypt(data), 16)
    except Exception:
        return data

# =============================================================================
# 📡 গ্যারেনা ইঞ্জিন
# =============================================================================
def inspect_token_openid(access_token):
    try:
        r = requests.get(f"https://100067.connect.garena.com/oauth/token/inspect?token={access_token}", headers={"User-Agent": "Mozilla/5.0"}, timeout=6, verify=False)
        d = r.json()
        if d.get("open_id"): return str(d.get("open_id"))
    except Exception: pass
    try:
        r = requests.get(f"https://100067.connect.garena.com/user/info?access_token={access_token}", headers={"User-Agent": "GarenaMSDK/5.5.2"}, timeout=6, verify=False)
        d = r.json()
        if d.get("open_id") or d.get("uid"): return str(d.get("open_id") or d.get("uid"))
    except Exception: pass
    return None

def get_player_profile(access_token):
    try:
        r = requests.get(f"https://api-otrss.garena.com/support/callback/?access_token={access_token}", headers={"User-Agent": "Mozilla/5.0"}, timeout=6, verify=False)
        q = urllib.parse.parse_qs(urllib.parse.urlparse(r.url).query)
        return q.get("account_id", ["Unknown"])[0], urllib.parse.unquote(q.get("nickname", ["Unknown"])[0]), q.get("region", ["Unknown"])[0]
    except Exception:
        return "Unknown", "Unknown", "Unknown"

def build_major_login_payload(open_id: str, access_token: str, platform_type: int) -> bytes:
    major = MajorLogin()
    major.event_time = str(datetime.now())[:-7]
    major.game_name = "free fire"
    major.platform_id = platform_type
    major.client_version = CLIENT_VERSION
    major.client_version_code = "2024010012"
    major.system_software = "Android OS 11 / API-30"
    major.system_hardware = "Handheld"
    major.telecom_operator = "Verizon"
    major.network_type = "WIFI"
    major.screen_width = 1080
    major.screen_height = 2400
    major.screen_dpi = "440"
    major.processor_details = "ARMv8"
    major.cpu_type = 2
    major.cpu_architecture = "64"
    major.memory = 6144
    major.gpu_renderer = "Adreno (TM) 650"
    major.gpu_version = "OpenGL ES 3.2"
    major.graphics_api = "OpenGLES3"
    major.unique_device_id = f"Google|{os.urandom(16).hex()}"
    major.language = "en"
    major.open_id = open_id
    major.open_id_type = str(platform_type)
    major.login_open_id_type = platform_type
    major.access_token = access_token
    major.login_by = 3
    major.platform_sdk_id = 1
    major.origin_platform_type = str(platform_type)
    major.primary_platform_type = str(platform_type)
    major.memory_available.version = 55
    major.memory_available.hidden_value = 81
    major.external_storage_total = 128512
    major.external_storage_available = 42000
    major.internal_storage_total = 110731
    major.internal_storage_available = 25000
    major.game_disk_storage_total = 26628
    major.game_disk_storage_available = 22000
    major.external_sdcard_total_storage = 119234
    major.external_sdcard_avail_storage = 50000
    major.library_path = "/data/app/~~random/base.apk"
    major.library_token = "hash|base.apk"
    major.client_using_version = "7428b253defc164018c604a1ebbfebdf"
    major.supported_astc_bitset = 16383
    major.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWAUOUgsvA1snWlBaO1kFYg=="
    major.loading_time = 13564
    major.release_channel = "android"
    major.channel_type = 3
    major.reg_avatar = 1
    major.if_push = 1
    major.is_vpn = 0
    major.android_engine_init_flag = 110009
    return enc_aes(major.SerializeToString())

def try_major_login_all_platforms(open_id: str, access_token: str):
    platform_types = [8, 3, 4, 6, 2, 5, 7, 1]
    url = "https://loginbp.ggpolarbear.com/MajorLogin"
    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; Android 13; SM-S918B)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB54"
    }
    for pt in platform_types:
        payload = build_major_login_payload(open_id, access_token, pt)
        try:
            r = requests.post(url, data=payload, headers=headers, timeout=8, verify=False)
            if r.status_code == 200:
                res = MajorLoginRes()
                try: res.ParseFromString(r.content)
                except Exception: res.ParseFromString(dec_aes(r.content))
                if res.token and res.url:
                    return res.token, res.url, res.account_uid, pt
        except Exception: continue
    return None, None, None, None

def upload_bio_verified(jwt_token: str, base_url: str, bio_text: str):
    try:
        data = BioData()
        data.field_2 = 17
        data.field_5.CopyFrom(EmptyMessage())
        data.field_6.CopyFrom(EmptyMessage())
        data.field_8 = bio_text
        data.field_9 = 1
        data.field_11.CopyFrom(EmptyMessage())
        data.field_12.CopyFrom(EmptyMessage())

        encrypted_payload = enc_aes(data.SerializeToString())
        headers = {
            "Expect": "100-continue",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB54",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Dalvik/2.1.0 (Linux; Android 11; SM-A305F)",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "Authorization": f"Bearer {jwt_token}"
        }
        target_url = f"{base_url}/UpdateSocialBasicInfo"
        r = requests.post(target_url, headers=headers, data=encrypted_payload, verify=False, timeout=10)
        return r.status_code == 200, r.status_code
    except Exception as e:
        return False, str(e)

# =============================================================================
# 🚀 FLASK APP (VERCEL SERVERLESS HANDLER)
# =============================================================================
app = Flask(__name__)

# CORS সাপোর্ট (যাতে মোবাইল অ্যাপ/ওয়েবসাইট থেকে সমস্যা ছাড়া কল করা যায়)
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
    return response

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "online",
        "service": "Free Fire Bio Changer API",
        "usage": "POST /api/bio with {'token': '...', 'bio': '...'}"
    })

# শুধুমাত্র বায়ো চেঞ্জ করার এন্ডপয়েন্ট
@app.route("/api/bio", methods=["GET", "POST"])
def change_bio():
    token = request.args.get("token")
    bio_text = request.args.get("bio")

    # JSON বডি থেকে ডাটা নেওয়া
    if request.is_json:
        data = request.json
        token = token or data.get("token")
        bio_text = bio_text or data.get("bio")

    if not token or not bio_text:
        return jsonify({
            "success": False,
            "error": "Missing 'token' or 'bio' parameter"
        }), 400

    # ২০০ ক্যারেক্টারের বেশি হলে ট্রাঙ্কেট করা
    if len(bio_text) > 200:
        bio_text = bio_text[:200]

    # ১. OpenID ও প্রোফাইল যাচাই
    open_id = inspect_token_openid(token)
    uid, nick, reg = get_player_profile(token)
    if not open_id and uid != "Unknown":
        open_id = uid

    if not open_id:
        return jsonify({
            "success": False,
            "error": "Invalid or expired token"
        }), 401

    # ২. MajorLogin অথেনটিকেশন
    jwt_token, base_url, acc_uid, pt = try_major_login_all_platforms(open_id, token)
    if not jwt_token or not base_url:
        return jsonify({
            "success": False,
            "error": "MajorLogin failed. Account might be banned or token expired."
        }), 403

    # ৩. গেম সার্ভারে বায়ো আপডেট
    success, res_info = upload_bio_verified(jwt_token, base_url, bio_text)
    if success:
        return jsonify({
            "success": True,
            "message": "Bio successfully updated!",
            "player": {
                "nickname": nick,
                "uid": acc_uid or uid,
                "region": reg
            },
            "updated_bio": bio_text
        }), 200
    else:
        return jsonify({
            "success": False,
            "error": f"Failed to upload on game server (Code: {res_info})"
        }), 500

app = app
