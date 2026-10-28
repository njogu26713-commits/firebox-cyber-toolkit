from __future__ import annotations
import hashlib, math, secrets, string

def generate_password(length: int = 20) -> str:
    if not 12 <= length <= 256:
        raise ValueError("password length must be between 12 and 256")
    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        value = ''.join(secrets.choice(alphabet) for _ in range(length))
        if all(any(c in group for c in value) for group in (string.ascii_lowercase, string.ascii_uppercase, string.digits, string.punctuation)):
            return value

def generate_token(length: int = 32) -> str:
    if not 16 <= length <= 256:
        raise ValueError("token length must be between 16 and 256 bytes")
    return secrets.token_urlsafe(length)

def strength(password: str) -> dict:
    if not isinstance(password, str): raise ValueError("password must be text")
    classes = sum(bool(set(password) & set(chars)) for chars in (string.ascii_lowercase, string.ascii_uppercase, string.digits, string.punctuation))
    entropy = len(password) * math.log2(max(1, sum(len(x) for x in (string.ascii_lowercase, string.ascii_uppercase, string.digits, string.punctuation))))
    score = min(4, max(0, (classes - 1) + (len(password) >= 16) + (len(password) >= 24)))
    return {"length": len(password), "character_classes": classes, "estimated_entropy_bits": round(entropy, 1), "score": score, "rating": ["very weak", "weak", "fair", "strong", "very strong"][score]}

def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""): digest.update(chunk)
    return digest.hexdigest()
