import os
import json
import base64
import socket
import time
import requests
from urllib.parse import urlparse, urlencode, quote
from concurrent.futures import ThreadPoolExecutor, as_completed

SOURCE = os.environ.get(
    "SOURCE_URL",
    "https://tiagorrg.github.io/vless-checker/keys.json"
)

OUT_DIR = os.environ.get("OUT_DIR", "docs")
TIMEOUT = float(os.environ.get("TIMEOUT", "3"))
MAX_SERVERS = int(os.environ.get("MAX_SERVERS", "200"))
MAX_WORKERS = int(os.environ.get("MAX_WORKERS", "20"))


def fetch_source():
    headers = {
        "User-Agent": "vpn-subscription-updater"
    }

    r = requests.get(SOURCE, timeout=30, headers=headers)
    r.raise_for_status()

    try:
        return r.json()
    except json.JSONDecodeError:
        # Если вдруг источник отдаёт не JSON, а текст со ссылками
        return r.text


def add_link(links, value):
    if not isinstance(value, str):
        return

    value = value.strip()

    if value.startswith("vless://") and value not in links:
        links.append(value)


def build_vless_link(obj):
    """
    Пытается собрать vless:// ссылку из объекта.
    Названия полей могут отличаться, поэтому берутся типовые варианты.
    """

    host = (
        obj.get("host")
        or obj.get("address")
        or obj.get("server")
        or obj.get("hostname")
    )

    port = obj.get("port")

    uuid = (
        obj.get("uuid")
        or obj.get("id")
        or obj.get("userId")
    )

    if not host or not port or not uuid:
        return None

    params = {}

    fields = [
        "security",
        "type",
        "network",
        "sni",
        "fp",
        "pbk",
        "sid",
        "flow",
        "path",
        "serviceName",
        "encryption",
        "allowInsecure",
        "headerType",
    ]

    for field in fields:
        value = obj.get(field)
        if value not in (None, ""):
            params[field] = str(value)

    name = (
        obj.get("name")
        or obj.get("remark")
        or obj.get("ps")
        or f"{host}:{port}"
    )

    query = urlencode(params)

    return f"vless://{uuid}@{host}:{port}?{query}#{quote(str(name))}"


def extract_links(data):
    links = []

    def walk(node):
        if isinstance(node, str):
            add_link(links, node)

        elif isinstance(node, dict):
            # Если где-то уже лежит готовая ссылка
            for key in ["link", "uri", "url", "config", "vless"]:
                value = node.get(key)
                if isinstance(value, str):
                    add_link(links, value)

            # Если это объект с параметрами сервера
            built = build_vless_link(node)
            if built:
                add_link(links, built)

            for value in node.values():
                walk(value)

        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(data)

    return links[:MAX_SERVERS]


def check_tcp(link):
    """
    Минимальная проверка: доступен ли TCP host:port.
    Для VLESS/Reality этого может быть недостаточно,
    но для первого этапа этого достаточно.
    """

    try:
        parsed = urlparse(link)
        host = parsed.hostname
        port = parsed.port or 443

        if not host:
            return False, 999999

        start = time.perf_counter()

        with socket.create_connection((host, port), timeout=TIMEOUT):
            latency_ms = int((time.perf_counter() - start) * 1000)
            return True, latency_ms

    except Exception:
        return False, 999999


def check_link_wrapper(link):
    ok, latency = check_tcp(link)
    return link, ok, latency


def main():
    data = fetch_source()
    links = extract_links(data)

    alive = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(check_link_wrapper, link) for link in links]

        for future in as_completed(futures):
            try:
                link, ok, latency = future.result()
                if ok:
                    alive.append({
                        "latency_ms": latency,
                        "link": link
                    })
            except Exception:
                pass

    alive.sort(key=lambda x: x["latency_ms"])

    os.makedirs(OUT_DIR, exist_ok=True)

    plain_links = "\n".join(x["link"] for x in alive)

    # Обычный текст со списком vless:// ссылок
    with open(os.path.join(OUT_DIR, "vless.txt"), "w", encoding="utf-8") as f:
        f.write(plain_links)

    # Base64-вариант для клиентов, которые ожидают base64 subscription
    with open(os.path.join(OUT_DIR, "vless-base64.txt"), "w", encoding="utf-8") as f:
        encoded = base64.b64encode(plain_links.encode("utf-8")).decode("ascii")
        f.write(encoded)

    # JSON-вариант для своих скриптов или клиентов, понимающих JSON
    payload = {
        "updated_unix": int(time.time()),
        "updated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": SOURCE,
        "checked": len(links),
        "alive": len(alive),
        "servers": [x["link"] for x in alive]
    }

    with open(os.path.join(OUT_DIR, "working.json"), "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    print(f"checked={len(links)} alive={len(alive)}")


if __name__ == "__main__":
    main()