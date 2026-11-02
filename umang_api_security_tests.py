"""Conservative API/web security checks for the UMANG chatbot endpoint.

This complements, but does not replace, the PyRIT LLM safety prompts.
Only target the endpoint and origin identified in the assessment evidence.
Run only with written authorization for these specific test cases.
No cookies, user tokens, account identifiers, concurrency, or destructive SQL are used.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
REPORTS = ROOT / "reports"
ENDPOINT = "https://apigw.umangapp.in/agenticBotApi/api/agent/query"
APP_ORIGIN = "https://web.umang.gov.in"
REFERER = "https://web.umang.gov.in/ai_chatbot/"
USER_AGENT = "UMANG-Authorized-Security-Assessment/1.0"
TIMEOUT = 20.0
INTER_TEST_DELAY_SECONDS = 1.5
MAX_RESPONSE_CHARS = 2500

# Heuristic indicators for review only. They do NOT automatically prove vulnerabilities.
ERROR_PATTERNS = re.compile(
    r"(?i)(traceback \(most recent call last\)|stack trace|sql syntax|sqlite error|"
    r"mysql error|postgresql error|ora-\d{4,}|sqlstate\[|unhandled exception|"
    r"internal server error at .+ line \d+)"
)


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def base_payload(question: str = "What services are available on UMANG?") -> dict[str, Any]:
    return {
        "question": question,
        "previousChats": [{"role": "user", "content": question}],
    }


def test_cases() -> list[dict[str, Any]]:
    return [
        {"id": "API-BASE-01", "category": "Baseline", "method": "POST", "body": base_payload(), "purpose": "Confirm a normal public query works."},
        {"id": "API-VAL-01", "category": "Input validation", "method": "POST", "body": {"previousChats": []}, "purpose": "Check missing question handling."},
        {"id": "API-VAL-02", "category": "Input validation", "method": "POST", "body": {"question": None, "previousChats": []}, "purpose": "Check null question handling."},
        {"id": "API-VAL-03", "category": "Input validation", "method": "POST", "body": {"question": 123, "previousChats": []}, "purpose": "Check wrong question data type handling."},
        {"id": "API-VAL-04", "category": "Input validation", "method": "POST", "body": {"question": "What services are available on UMANG?", "previousChats": "not-an-array"}, "purpose": "Check wrong previousChats data type handling."},
        {"id": "API-VAL-05", "category": "Malformed request", "method": "POST", "raw_body": '{"question":', "content_type": "application/json", "purpose": "Check malformed JSON handling."},
        {"id": "API-VAL-06", "category": "Content-Type handling", "method": "POST", "raw_body": json.dumps(base_payload()), "content_type": "text/plain", "purpose": "Check whether unsupported content type is rejected or handled safely."},
        {"id": "API-INJ-01", "category": "SQL-like input handling", "method": "POST", "body": base_payload("UMANG' OR '1'='1"), "purpose": "Low-impact SQL metacharacter/boolean-like input probe; not a destructive SQL test."},
        {"id": "API-XSS-01", "category": "HTML/XSS reflection", "method": "POST", "body": base_payload("Please repeat this literal marker exactly: <script>UMANG_XSS_SENTINEL</script>"), "purpose": "Check whether inert HTML marker is reflected in the JSON response; browser DOM validation is still required."},
        {"id": "API-CORS-01", "category": "CORS trusted origin", "method": "POST", "body": base_payload(), "origin": APP_ORIGIN, "purpose": "Observe CORS response for the known application origin."},
        {"id": "API-CORS-02", "category": "CORS untrusted origin", "method": "POST", "body": base_payload(), "origin": "https://security-test.invalid", "purpose": "Check that an unrelated origin is not granted credentialed CORS access."},
        {"id": "API-CORS-03", "category": "CORS preflight", "method": "OPTIONS", "origin": "https://security-test.invalid", "extra_headers": {"Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type,authorization"}, "purpose": "Inspect preflight response for an unrelated origin."},
        {"id": "API-AUTH-01", "category": "Public endpoint auth behavior", "method": "POST", "body": base_payload(), "purpose": "Record behavior without Authorization; public anonymous access may be expected for this chatbot."},
        {"id": "API-AUTH-02", "category": "Invalid auth header behavior", "method": "POST", "body": base_payload(), "auth_header": "Bearer invalid-assessment-token", "purpose": "Observe whether malformed credentials alter behavior; success is not a bypass finding if the endpoint is intentionally public."},
        {"id": "API-METHOD-01", "category": "HTTP method handling", "method": "GET", "purpose": "Check whether GET is rejected or safely handled."},
        {"id": "API-METHOD-02", "category": "HTTP method handling", "method": "HEAD", "purpose": "Check whether HEAD is rejected or safely handled."},
        {"id": "API-METHOD-03", "category": "HTTP method handling", "method": "OPTIONS", "purpose": "Record advertised methods and CORS-related headers."},
        {"id": "API-RATE-01A", "category": "Low-rate resource-control observation", "method": "POST", "body": base_payload(), "delay_seconds": 3.0, "purpose": "Sequential sample 1 of 4; observe status and Retry-After without a burst."},
        {"id": "API-RATE-01B", "category": "Low-rate resource-control observation", "method": "POST", "body": base_payload(), "delay_seconds": 3.0, "purpose": "Sequential sample 2 of 4; observe status and Retry-After without a burst."},
        {"id": "API-RATE-01C", "category": "Low-rate resource-control observation", "method": "POST", "body": base_payload(), "delay_seconds": 3.0, "purpose": "Sequential sample 3 of 4; observe status and Retry-After without a burst."},
        {"id": "API-RATE-01D", "category": "Low-rate resource-control observation", "method": "POST", "body": base_payload(), "delay_seconds": 3.0, "purpose": "Sequential sample 4 of 4; observe status and Retry-After without a burst."},
    ]


def sanitize_headers(headers: httpx.Headers) -> dict[str, str]:
    interesting = [
        "content-type", "content-length", "allow", "access-control-allow-origin",
        "access-control-allow-credentials", "access-control-allow-methods",
        "access-control-allow-headers", "access-control-max-age", "vary",
        "strict-transport-security", "x-content-type-options", "content-security-policy",
        "x-frame-options", "referrer-policy", "permissions-policy", "retry-after",
        "server", "x-powered-by", "date",
    ]
    out = {}
    for key in interesting:
        value = headers.get(key)
        if value is not None:
            out[key] = value[:500]
    return out


def summarize_response(resp: httpx.Response, case: dict[str, Any]) -> dict[str, Any]:
    try:
        parsed = resp.json()
    except Exception:
        parsed = None
    body = resp.text[:MAX_RESPONSE_CHARS]
    answer = parsed.get("answer") if isinstance(parsed, dict) else None
    raw = body
    flags: list[str] = []
    if resp.status_code == 429:
        flags.append("rate_limit_response_observed")
    if resp.status_code >= 500:
        flags.append("server_error_observed")
    if ERROR_PATTERNS.search(body):
        flags.append("possible_verbose_error_or_database_error_text")
    if case.get("id") == "API-XSS-01" and "UMANG_XSS_SENTINEL" in body:
        flags.append("xss_marker_reflected_in_response_review_frontend_dom")
    origin = case.get("origin")
    allow_origin = resp.headers.get("access-control-allow-origin")
    if origin and origin != APP_ORIGIN and allow_origin in {origin, "*"}:
        flags.append("untrusted_origin_appears_in_access_control_allow_origin")
    if origin and origin != APP_ORIGIN and resp.headers.get("access-control-allow-credentials", "").lower() == "true" and allow_origin == "*":
        flags.append("cors_wildcard_with_credentials_header_review")
    if case.get("id") == "API-AUTH-02":
        flags.append("auth_result_requires_design_context_not_an_automatic_finding")
    if case.get("category") == "SQL-like input handling":
        flags.append("sql_like_string_probe_requires_backend_evidence_not_an_automatic_finding")
    if case.get("category") == "HTTP method handling":
        flags.append("method_response_requires_expected_route_contract")

    if flags:
        triage = "MANUAL_REVIEW_REQUIRED"
    elif resp.status_code >= 500:
        triage = "POTENTIAL_SERVER_ERROR_REVIEW"
    else:
        triage = "OBSERVATION_REVIEW"
    return {
        "http_status": resp.status_code,
        "response_headers": sanitize_headers(resp.headers),
        "content_type": resp.headers.get("content-type"),
        "api_success": parsed.get("success") if isinstance(parsed, dict) else None,
        "answer_excerpt": answer[:MAX_RESPONSE_CHARS] if isinstance(answer, str) else None,
        "response_excerpt": raw,
        "intents": parsed.get("intents") if isinstance(parsed, dict) else None,
        "authenticated": parsed.get("authenticated") if isinstance(parsed, dict) else None,
        "triage_flags": flags,
        "triage": triage,
        "note": "Observed behavior is not a vulnerability verdict. Validate against intended design and, for XSS/SQLi/auth findings, collect appropriate browser/backend/authorization evidence.",
    }


def send_case(client: httpx.Client, case: dict[str, Any]) -> dict[str, Any]:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
        "Origin": case.get("origin", APP_ORIGIN),
        "Referer": REFERER,
    }
    headers.update(case.get("extra_headers", {}))
    if case.get("auth_header"):
        headers["Authorization"] = case["auth_header"]
    content = None
    json_body = None
    if "body" in case:
        json_body = case["body"]
        headers["Content-Type"] = "application/json"
    elif "raw_body" in case:
        content = case["raw_body"].encode("utf-8")
        headers["Content-Type"] = case.get("content_type", "application/json")
    elif case["method"] == "OPTIONS":
        headers["Access-Control-Request-Method"] = case.get("extra_headers", {}).get("Access-Control-Request-Method", "POST")
    try:
        resp = client.request(case["method"], ENDPOINT, headers=headers, json=json_body, content=content)
        return {**case_public(case), "captured_at_utc": now(), **summarize_response(resp, case)}
    except httpx.HTTPError as exc:
        return {
            **case_public(case), "captured_at_utc": now(), "http_status": None,
            "request_error": f"{type(exc).__name__}: {str(exc)[:300]}",
            "response_headers": {}, "triage": "REQUEST_ERROR_OR_REVIEW", "triage_flags": [],
        }


def case_public(case: dict[str, Any]) -> dict[str, Any]:
    # Do not serialize arbitrary headers or request contents into metadata.
    keys = ["id", "category", "method", "purpose"]
    return {key: case[key] for key in keys if key in case}


def write_report(report: dict[str, Any], path: Path) -> None:
    lines = [
        "# UMANG Chatbot — API-Level Security Checks (Low-Impact Extension)", "",
        f"- Started (UTC): `{report['started_utc']}`",
        f"- Finished (UTC): `{report['finished_utc']}`",
        f"- Endpoint: `{ENDPOINT}`",
        f"- Requests attempted: {report['summary']['attempted']}",
        f"- Responses received: {report['summary']['responses_received']}",
        "", "## Scope and safety limits", "",
        "This is a low-impact supplement to the PyRIT LLM safety run. It checks basic request validation, content-type handling, method behavior, CORS responses, public/invalid-auth behavior, harmless SQL-like input, inert HTML-marker reflection, and a small sequential rate observation.",
        "It does not perform credential guessing, access other users' data, destructive SQL, active XSS execution, endpoint brute forcing, concurrency, load testing, or rate-limit exhaustion. Do not infer a broken-authentication finding from an unauthenticated 200 on a potentially public chatbot endpoint.",
        "", "## Summary", "",
        "| ID | Category | Method | HTTP | Triage | Flags |", "|---|---|---|---:|---|---|",
    ]
    for r in report["results"]:
        flags = ", ".join(r.get("triage_flags", [])) or "None auto-flagged"
        lines.append(f"| {r['id']} | {r['category']} | {r['method']} | {r.get('http_status', 'N/A')} | {r.get('triage', 'N/A')} | {flags} |")
    lines += ["", "## Detailed observations", ""]
    for r in report["results"]:
        lines += [
            f"### {r['id']} — {r['category']}", "",
            f"**Request purpose:** {r.get('purpose', '')}", "",
            f"**Method / HTTP status:** `{r.get('method')}` / `{r.get('http_status', 'N/A')}`", "",
            f"**Triage:** `{r.get('triage', 'N/A')}`", "",
            f"**Flags:** {', '.join(r.get('triage_flags', [])) or 'None auto-flagged'}", "",
            "**Selected response headers:**", "", "```json",
            json.dumps(r.get("response_headers", {}), ensure_ascii=False, indent=2), "```", "",
            "**Response excerpt (redacted/bounded):**", "", "```text",
            (r.get("answer_excerpt") or r.get("response_excerpt") or r.get("request_error") or "No response body").replace("```", "'''"), "```", "",
            r.get("note", ""), "",
        ]
    lines += [
        "## Important interpretation notes", "",
        "- SQL-like text in a chatbot question does not prove SQL injection. SQLi must be tied to an input that actually reaches a database query or produce reliable backend evidence. This probe is a low-impact indicator only.",
        "- An HTML tag appearing in JSON is not proof of XSS. Verify whether the browser renders the value as executable DOM rather than text, using the authorized frontend and a harmless marker.",
        "- CORS response headers affect browsers, not command-line clients. Inspect whether untrusted origins receive `Access-Control-Allow-Origin` and whether credentials are allowed.",
        "- The query route may intentionally be public. Authentication/authorization coverage for protected user data requires a documented protected endpoint and approved test accounts/roles, preferably in staging.",
        "- The request sample does not prove rate limiting is absent. It is not a load test. Confirm the approved threshold and test in staging or under a written production test window before increasing request volume.",
        "- Unsupported HTTP methods, missing fields, and malformed JSON can yield different statuses depending on the API contract. Compare to documented expected behavior before filing findings.",
        "", "## Next tests requiring owner-provided scope", "",
        "1. Authentication and authorization: owner-supplied endpoint inventory, expected-public/protected classification, and two dedicated test accounts for object/function-level access-control checks.",
        "2. Rate limiting/resource consumption: approved threshold, test window, stop conditions, and staging or explicit monitoring/rollback plan. Do not perform production exhaustion testing.",
        "3. XSS: browser validation of the rendered DOM and output encoding, not just the JSON API response.",
        "4. SQL injection: only test data-bearing/search/auth endpoints with a confirmed database interaction and owner-approved non-destructive cases.",
        "5. Broader API inventory: use permitted documentation and observed network calls; do not brute-force guessed endpoints.",
        "", "## Standards alignment", "",
        "This small set touches a subset of API security considerations, such as input validation, security misconfiguration, authentication assumptions, and resource-consumption observations. It is not a complete OWASP API Security Top 10 assessment.",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm-authorized", action="store_true", help="Confirm written authorization covers these low-impact endpoint checks.")
    parser.add_argument("--delay", type=float, default=INTER_TEST_DELAY_SECONDS, help="Seconds between requests (default: 1.5; minimum 1.0).")
    args = parser.parse_args()
    if not args.confirm_authorized:
        print("Refusing to run without --confirm-authorized and owner approval for this exact test scope.", file=sys.stderr)
        return 2
    if args.delay < 1.0:
        print("Delay must be at least 1.0 second; this script is deliberately low-rate.", file=sys.stderr)
        return 2

    RESULTS.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    started = now()
    results: list[dict[str, Any]] = []
    cases = test_cases()
    limits = httpx.Limits(max_connections=1, max_keepalive_connections=1)
    with httpx.Client(timeout=TIMEOUT, follow_redirects=False, verify=True, limits=limits) as client:
        for index, case in enumerate(cases, 1):
            if index > 1:
                time.sleep(max(args.delay, float(case.get("delay_seconds", args.delay))))
            print(f"[{index}/{len(cases)}] {case['id']} — {case['category']}")
            result = send_case(client, case)
            results.append(result)
            print(f"    HTTP {result.get('http_status', 'ERROR')} | {result.get('triage', 'N/A')}")

    report = {
        "report_title": "UMANG Chatbot API-Level Security Checks — Low-Impact Extension",
        "started_utc": started,
        "finished_utc": now(),
        "target_endpoint": ENDPOINT,
        "methodology": "Sequential, low-rate, non-destructive API behavior probes; no auth secrets or user data.",
        "authorization_confirmed_by_operator": True,
        "summary": {
            "attempted": len(results),
            "responses_received": sum(1 for r in results if r.get("http_status") is not None),
            "request_errors": sum(1 for r in results if r.get("http_status") is None),
            "items_requiring_review": sum(1 for r in results if r.get("triage_flags")),
        },
        "results": results,
    }
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    json_path = RESULTS / f"api_security_results_{stamp}.json"
    md_path = REPORTS / f"api_security_report_{stamp}.md"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    write_report(report, md_path)
    (RESULTS / "api_security_results_latest.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    (REPORTS / "api_security_report_latest.md").write_text(md_path.read_text(encoding="utf-8"), encoding="utf-8")
    print("\nFinished. Results are observations, not automatic vulnerability verdicts.")
    print(f"JSON evidence: {json_path}")
    print(f"Markdown report: {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
