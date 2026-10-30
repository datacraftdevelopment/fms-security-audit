"""Pack and unpack the result block printed by the OS scripts."""

import base64
import gzip
import hashlib
import json
import re

BEGIN = "----- FMS-AUDIT OS BEGIN v1 -----"
END = "----- FMS-AUDIT OS END -----"


class BlockError(ValueError):
    pass


def encode(data):
    raw = json.dumps(data, separators=(",", ":")).encode("utf-8")
    b64 = base64.b64encode(gzip.compress(raw)).decode("ascii")
    lines = "\n".join(b64[i : i + 76] for i in range(0, len(b64), 76))
    return f"{BEGIN}\n{lines}\nsha256: {hashlib.sha256(raw).hexdigest()}\n{END}"


def decode(text):
    text = text.replace("\r", "")
    start, end = text.find(BEGIN), text.find(END)
    if start < 0 or end < 0:
        raise BlockError("No FMS-AUDIT block found. Copy everything from the BEGIN line to the END line.")
    body = text[start + len(BEGIN) : end].strip().splitlines()
    sha_line = next((l for l in body if l.startswith("sha256:")), None)
    if sha_line is None:
        raise BlockError("The block has no checksum line; it was probably cut off.")
    payload = re.sub(r"\s", "", "".join(l for l in body if not l.startswith("sha256:")))
    try:
        raw = gzip.decompress(base64.b64decode(payload))
    except Exception as exc:
        raise BlockError("The block is damaged; copy it again from BEGIN to END.") from exc
    if hashlib.sha256(raw).hexdigest() != sha_line.split(":", 1)[1].strip():
        raise BlockError("Checksum mismatch; the block was cut off or altered. Copy it again.")
    return json.loads(raw.decode("utf-8"))
