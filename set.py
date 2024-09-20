import json
import os

CODES_FILE = 'codes.json'

def load_codes():
    if not os.path.exists(CODES_FILE):
        # 초기 암호 설정
        codes = {
            "user_code": "user1234",
            "admin_code": "admin1234"
        }
        save_codes(codes)
    else:
        with open(CODES_FILE, 'r', encoding='utf-8') as f:
            codes = json.load(f)
    return codes

def save_codes(codes):
    with open(CODES_FILE, 'w', encoding='utf-8') as f:
        json.dump(codes, f, ensure_ascii=False, indent=4)
