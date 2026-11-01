"""Cross-Origin Resource Sharing (CORS) policy and preflight evaluation rules."""

from __future__ import annotations

from collections.abc import Mapping

from lh_web_auditor.models import Category, CorsProbeResult, Finding, Severity


def evaluate_cors_response(
    preflight_headers: Mapping[str, str],
    tested_origin: str,
    status_code: int = 200,
) -> tuple[CorsProbeResult, list[Finding]]:
    """Evaluate preflight / CORS response headers against origin reflection and wildcard risks.

    Args:
        preflight_headers: Response headers returned from the preflight / probe request.
        tested_origin: The origin value passed in the test request.
        status_code: HTTP response status code of the probe response.

    Returns:
        A tuple of (CorsProbeResult, list of detected Finding objects).
    """
    normalized = {k.lower(): v.strip() for k, v in preflight_headers.items()}
    allow_origin = normalized.get("access-control-allow-origin")
    allow_credentials_raw = normalized.get("access-control-allow-credentials", "")
    allow_credentials = allow_credentials_raw.lower() == "true"

    allow_methods_raw = normalized.get("access-control-allow-methods", "")
    allow_methods = [m.strip() for m in allow_methods_raw.split(",") if m.strip()]

    allow_headers_raw = normalized.get("access-control-allow-headers", "")
    allow_headers = [h.strip() for h in allow_headers_raw.split(",") if h.strip()]

    findings: list[Finding] = []

    is_wildcard = allow_origin == "*"
    is_reflected = (
        allow_origin is not None
        and tested_origin.lower() in allow_origin.lower()
        and not is_wildcard
    )
    is_null_trusted = allow_origin is not None and allow_origin.lower() == "null"
    is_vulnerable = False

    if allow_origin is not None:
        # Case 1: Arbitrary Origin Reflection WITH Credentials Allowed (Critical!)
        if is_reflected and allow_credentials:
            is_vulnerable = True
            findings.append(
                Finding(
                    id="SEC-CORS-REFLECTED-CREDENTIALS",
                    title="CORS Arbitrary Origin Reflection with Credentials Allowed",
                    category=Category.CORS,
                    severity=Severity.CRITICAL,
                    description=(
                        "The server reflects arbitrary client-supplied Origin headers and permits "
                        "authenticated credentials (Access-Control-Allow-Credentials: true). "
                        "Malicious sites can issue authenticated requests to read user data."
                    ),
                    evidence=(
                        f"Sent Origin: {tested_origin} -> Received ACAO: {allow_origin}, "
                        f"ACAC: {allow_credentials_raw}"
                    ),
                    recommendation=(
                        "Validate the Origin against an explicit server-side whitelist. Never "
                        "echo the request Origin when credentials are supported."
                    ),
                    cwe_id="CWE-942",
                )
            )

        # Case 2: Wildcard WITH Credentials Allowed
        elif is_wildcard and allow_credentials:
            is_vulnerable = True
            findings.append(
                Finding(
                    id="SEC-CORS-WILDCARD-CREDENTIALS",
                    title="CORS Wildcard Origin with Credentials Allowed",
                    category=Category.CORS,
                    severity=Severity.CRITICAL,
                    description=(
                        "Access-Control-Allow-Origin is '*' while Access-Control-Allow-Credentials "
                        "is 'true'. Modern browsers reject this combination."
                    ),
                    evidence="ACAO: *, ACAC: true",
                    recommendation="Remove wildcard origin when credentials are required.",
                    cwe_id="CWE-942",
                )
            )

        # Case 3: Arbitrary Origin Reflection WITHOUT Credentials
        elif is_reflected and not allow_credentials:
            is_vulnerable = True
            findings.append(
                Finding(
                    id="SEC-CORS-REFLECTED-NO-CREDENTIALS",
                    title="CORS Arbitrary Origin Reflection",
                    category=Category.CORS,
                    severity=Severity.HIGH,
                    description=(
                        "The server echoes arbitrary Origin headers into "
                        "Access-Control-Allow-Origin. Third-party sites can read API responses."
                    ),
                    evidence=f"Sent Origin: {tested_origin} -> Received ACAO: {allow_origin}",
                    recommendation="Enforce a strict whitelist of legitimate origins for CORS.",
                    cwe_id="CWE-942",
                )
            )

        # Case 4: Null Origin Trusted
        elif is_null_trusted:
            is_vulnerable = True
            findings.append(
                Finding(
                    id="SEC-CORS-NULL-ORIGIN",
                    title="CORS Policy Trusts 'null' Origin",
                    category=Category.CORS,
                    severity=Severity.HIGH,
                    description=(
                        "The CORS policy permits the 'null' origin. Attackers can trigger "
                        "requests from sandboxed iframes to bypass origin verification."
                    ),
                    evidence=f"ACAO: {allow_origin}",
                    recommendation="Disallow 'null' origins; use explicit domain whitelists.",
                    cwe_id="CWE-942",
                )
            )

        # Case 5: Overly Permissive Wildcard Origin
        elif is_wildcard:
            findings.append(
                Finding(
                    id="SEC-CORS-WILDCARD",
                    title="CORS Policy Uses Wildcard (*)",
                    category=Category.CORS,
                    severity=Severity.LOW,
                    description=(
                        "Access-Control-Allow-Origin is set to '*'. This should be avoided "
                        "on endpoints returning sensitive or private data."
                    ),
                    evidence="ACAO: *",
                    recommendation="Verify that this resource is intended for public access.",
                    cwe_id="CWE-942",
                )
            )

    probe_result = CorsProbeResult(
        tested_origin=tested_origin,
        allow_origin=allow_origin,
        allow_credentials=allow_credentials,
        allow_methods=allow_methods,
        allow_headers=allow_headers,
        status_code=status_code,
        is_wildcard=is_wildcard,
        is_reflected=is_reflected,
        is_vulnerable=is_vulnerable,
    )

    return probe_result, findings
