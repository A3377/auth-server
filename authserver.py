from flask import Flask, request, jsonify
import hashlib, random, string, time, requests

app = Flask(__name__)
APK_HASHES = ["ABC123XYZ789HASHVALUE"]
ISSUED_CHALLENGES = {}
TOKEN_EXPIRY = 30

def generate_challenge():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=16)) + "="

@app.route("/auth", methods=["POST"])
def auth():
    data = request.json
    token = data.get("token")
    device = data.get("device")
    fingerprint = data.get("fingerprint")

    if not token or not isinstance(token, str):
        print("Invalid token format:", token)
        return jsonify({"status": "rejected", "reason": "JS Auth Server error: 0011 \nInvalid Token Format"})

    if device not in ["ANDROID", "VR"]:
        print("Unsupported device:", device)
        return jsonify({"status": "rejected", "reason": "JS Auth Server error: 0010 \nUnsupported Device"})

print("Skipping JS validation for token:", token)

    challenge = generate_challenge()
    ISSUED_CHALLENGES[token] = (challenge, time.time())
    print("Token accepted:", token, "Challenge issued:", challenge)
    return jsonify({"status": "pending", "challenge": challenge})

@app.route("/challenge", methods=["POST"])
def challenge():
    data = request.json
    token = data.get("token")
    fingerprint = data.get("fingerprint")
    device = data.get("device")
    apk_hash = data.get("apk_hash")
    response_hash = data.get("response")

    if token not in ISSUED_CHALLENGES:
        print("Token not issued:", token)
        return jsonify({"status": "rejected", "reason": "Token Not Issued Threw Client"})

    challenge, timestamp = ISSUED_CHALLENGES[token]
    if time.time() - timestamp > TOKEN_EXPIRY:
        del ISSUED_CHALLENGES[token]
        print("Token expired:", token)
        return jsonify({"status": "rejected", "reason": "This Token Is Expired"})

    if apk_hash not in APK_HASHES:
        print("Invalid APK hash:", apk_hash)
        return jsonify({"status": "rejected", "reason": "invalid_apk_hash"})

    expected_hash = hashlib.sha256(f"{token}{challenge}{fingerprint}{apk_hash}".encode()).digest()
    expected_hash_b64 = expected_hash.hex()
    if response_hash != expected_hash_b64 and response_hash != expected_hash_b64.upper():
        print("Invalid challenge response:", token)
        return jsonify({"status": "rejected", "reason": "Challenge Reponse Data Is Invalid"})

    del ISSUED_CHALLENGES[token]
    print("Token validated successfully:", token)
    return jsonify({"status": "success"})

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

