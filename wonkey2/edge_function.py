import base64
import copy
import hashlib
import json
import re
import secrets
import urllib.parse
from typing import Optional, Dict, Union, List

_SENTINEL = object()

GENERATED_KEY_BYTES = 16

BUILT_IN_RESPONSES = {
    "/": lambda event: {
        "status": "302" if get_psuedo_env_var(event, "root-redirect-url") else "204",
        "body": "",
        "headers": as_headers(
            {"location": get_psuedo_env_var(event, "root-redirect-url")}
            if get_psuedo_env_var(event, "root-redirect-url")
            else {}
        ),
    },
    "/favicon.ico": lambda event: {
        "status": "200",
        "body": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABAQAAAAA3bvkkAAAACklEQVR4AWNgAAAAAgABc3UBGAAAAABJRU5ErkJggg==",
        "bodyEncoding": "base64",
        "headers": as_headers(
            {
                "content-type": "image/png",
            }
        ),
    },
    "/robots.txt": lambda event: {
        "status": "200",
        "body": "User-agent: *\nDisallow: /",
        "headers": as_headers(
            {
                "content-type": "text/plain",
            }
        ),
    },
    "/sharex.json": lambda event: {
        "status": "200",
        "body": json.dumps(
            {
                "Version": "13.4.0",
                "DestinationType": "ImageUploader, TextUploader, FileUploader",
                "RequestMethod": "PUT",
                "RequestURL": "".join(
                    (
                        "https://",
                        get_psuedo_env_var(event, "domain-name")
                        or event["config"]["distributionDomainName"],
                        "/$filename$",
                    )
                ),
                "Body": "Binary",
                "URL": "".join(
                    (
                        "https://",
                        get_psuedo_env_var(event, "domain-name")
                        or event["config"]["distributionDomainName"],
                        "/$json:key$",
                    )
                ),
                **(
                    {"Headers": {"x-wonkey-password": "$prompt:Upload password?$"}}
                    if get_psuedo_env_var(event, "upload-password")
                    else {}
                ),
            }
        ),
        "headers": as_headers(
            {
                "content-type": "application/json",
            }
        ),
    },
}


def b64encode(
    data: Union[str, bytes],
    altchars: Optional[Union[str, bytes]] = None,
    strip_padding: bool = False,
) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    if isinstance(altchars, str):
        altchars = altchars.encode("utf-8")
    encoded = base64.b64encode(data, altchars=altchars).decode("utf-8")
    if strip_padding:
        return encoded.rstrip("=")
    return encoded


def b64decode(data: str, altchars: Optional[Union[str, bytes]] = None) -> bytes:
    if isinstance(altchars, str):
        altchars = altchars.encode("utf-8")
    return base64.b64decode(data + (len(data) % 4 * "="), altchars=altchars)


def as_headers(headers: Dict[str, str]) -> Dict[str, List[Dict[str, str]]]:
    return {k: [{"value": v}] for k, v in headers.items()}


def get_header(headers: dict, key: str, default=_SENTINEL):
    if key.lower() in headers:
        return headers[key.lower()][0]["value"]
    elif default is not _SENTINEL:
        return default
    raise KeyError(f"Header {key!r} not found")


def get_psuedo_env_var(event: dict, key: str) -> str:
    """
    Retrieves a configuration variable stored in the distribution's origin configuration,
    since Lambda@Edge does not support traditional environment variables.
    """
    return get_header(
        event["request"]["origin"]["s3"]["customHeaders"], f"x-wonkey-{key}"
    )


def pad_encryption_key(
    encryption_key: bytes, length: int, fill: bytes = b"\x00"
) -> bytes:
    """
    Right-pad an encryption key to meet a certain length requirement.
    This lets us use 128-bit keys with the required 256-bit algorithm (for shorter URLs).
    """
    if len(encryption_key) > length:
        raise ValueError("Key is already longer than intended padding")
    return encryption_key.ljust(length, fill)


def key_to_sse_headers(key: bytes) -> dict:
    aes256_key_length = 32
    return {
        "x-amz-server-side-encryption-customer-algorithm": "AES256",
        "x-amz-server-side-encryption-customer-key": b64encode(
            pad_encryption_key(key, aes256_key_length)
        ),
        "x-amz-server-side-encryption-customer-key-MD5": b64encode(
            hashlib.md5(pad_encryption_key(key, aes256_key_length)).digest()
        ),
    }


def filter_required_headers(event_type: str, headers: dict) -> dict:
    """
    Filters a response headers dict to the values required in responses by
    CloudFront's rules on "read-only" headers: https://amzn.to/2ReI6Oj
    This currently only supports origin-response because that's only place I needed to do this.
    """
    read_only_headers = {"origin-response": {"transfer-encoding", "via"}}
    return {k: v for k, v in headers.items() if k in read_only_headers[event_type]}


def is_unhappy_status_code(code: str) -> bool:
    return not re.match(r"^(304|2[0-9]{2})$", code)


def check_upload_password_valid(event: dict) -> bool:
    expected_password = get_psuedo_env_var(event, "upload-password")
    provided_password = get_header(event["request"]["headers"], "x-wonkey-password", "")
    if not expected_password:
        return True
    return secrets.compare_digest(expected_password, provided_password)


def handle_origin_request_get(event: dict) -> dict:
    if event["request"]["uri"] in BUILT_IN_RESPONSES:
        return BUILT_IN_RESPONSES[event["request"]["uri"]](event)
    if match := re.search(r"^/([A-Za-z0-9-_]{22})", event["request"]["uri"]):
        request = copy.deepcopy(event["request"])
        key = b64decode(match.group(1), altchars="-_")
        request["uri"] = "/" + hashlib.sha256(key).hexdigest()
        request["headers"].update(as_headers(key_to_sse_headers(key)))
        return request
    return {"status": "404"}


def handle_origin_response_get(event: dict) -> dict:
    if is_unhappy_status_code(event["response"]["status"]):
        return {
            "status": "404",
            "headers": filter_required_headers(
                event["config"]["eventType"], event["response"]["headers"]
            ),
            "body": "",
        }
    response = copy.deepcopy(event["response"])
    if b64_filename := get_header(response["headers"], "x-amz-meta-filename", None):
        filename = b64decode(b64_filename).decode("utf-8", errors="replace")
        ascii_filename = re.sub(r"[^A-Za-z0-9._\- ]+", "_", filename)
        quoted_filename = urllib.parse.quote(filename)
        response["headers"].update(
            as_headers(
                {
                    "content-disposition": "; ".join(
                        (
                            "inline",
                            f"filename={ascii_filename}",
                            f"filename*=UTF-8''{quoted_filename}",
                        )
                    ),
                }
            )
        )
    for amz_header in set(
        k for k in response["headers"].keys() if k.startswith("x-amz-")
    ):
        del response["headers"][amz_header]
    return response


def handle_origin_request_put(event: dict) -> dict:
    if not check_upload_password_valid(event):
        return {"status": "403"}
    if match := re.match(
        r"^([0-9]+)$", get_header(event["request"]["headers"], "content-length", "")
    ):
        if int(match.group(1)) > 5 * 1024 * 1024 * 1024:
            return {"status": "413"}
    request = copy.deepcopy(event["request"])
    key = secrets.token_bytes(GENERATED_KEY_BYTES)
    request["uri"] = "/" + hashlib.sha256(key).hexdigest()
    request["headers"].update(
        as_headers(
            {
                "x-amz-acl": "bucket-owner-full-control",
                "x-amz-meta-filename": b64encode(
                    urllib.parse.unquote(event["request"]["uri"][1:])
                ),
                **key_to_sse_headers(key),
            }
        )
    )
    return request


def handle_origin_response_put(event: dict) -> dict:
    key = b64decode(
        get_header(
            event["request"]["headers"], "x-amz-server-side-encryption-customer-key"
        )
    )[:GENERATED_KEY_BYTES]
    encoded_key = b64encode(key, altchars="-_", strip_padding=True)
    return {
        "status": "202",
        "headers": {
            **as_headers(
                {
                    "content-type": "application/json",
                }
            ),
            **filter_required_headers(
                event["config"]["eventType"], event["response"]["headers"]
            ),
        },
        "body": json.dumps({"key": encoded_key}),
    }


def handler(event: dict, _context=None) -> dict:
    handlers = {
        ("origin-request", "GET"): handle_origin_request_get,
        ("origin-request", "PUT"): handle_origin_request_put,
        ("origin-response", "GET"): handle_origin_response_get,
        ("origin-response", "PUT"): handle_origin_response_put,
    }
    cf = event["Records"][0]["cf"]
    print("Received event:", json.dumps(cf))
    if handler := handlers.get((cf["config"]["eventType"], cf["request"]["method"])):
        response = handler(cf)
    else:
        response = {"status": "405"}
    print("Function response:", json.dumps(response))
    return response
