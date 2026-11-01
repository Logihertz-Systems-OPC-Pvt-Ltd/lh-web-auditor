"""Cookie security attribute inspection rules."""

from __future__ import annotations

from collections.abc import Sequence

from lh_web_auditor.models import Category, CookieFinding, Finding, Severity


def parse_cookie_header(header_value: str) -> CookieFinding:
    """Parse a single Set-Cookie header string into a structured CookieFinding."""
    parts = [p.strip() for p in header_value.split(";") if p.strip()]
    if not parts:
        return CookieFinding(
            name="<unnamed>",
            secure=False,
            httponly=False,
            samesite=None,
            path=None,
            domain=None,
            raw=header_value,
        )

    name_value = parts[0].split("=", 1)
    cookie_name = name_value[0].strip()

    secure = False
    httponly = False
    samesite: str | None = None
    path: str | None = None
    domain: str | None = None

    for attribute in parts[1:]:
        attr_parts = attribute.split("=", 1)
        attr_name = attr_parts[0].strip().lower()
        attr_val = attr_parts[1].strip() if len(attr_parts) > 1 else ""

        if attr_name == "secure":
            secure = True
        elif attr_name == "httponly":
            httponly = True
        elif attr_name == "samesite":
            samesite = attr_val or "Lax"
        elif attr_name == "path":
            path = attr_val
        elif attr_name == "domain":
            domain = attr_val

    return CookieFinding(
        name=cookie_name,
        secure=secure,
        httponly=httponly,
        samesite=samesite,
        path=path,
        domain=domain,
        raw=header_value,
    )


def evaluate_cookies(
    cookie_headers: Sequence[str], is_https: bool
) -> tuple[list[CookieFinding], list[Finding]]:
    """Audit all Set-Cookie headers for missing security flags and prefix conformity.

    Args:
        cookie_headers: List of raw Set-Cookie header strings.
        is_https: True if the audited request was over TLS/HTTPS.

    Returns:
        A tuple of (parsed_cookie_findings, security_findings).
    """
    cookies: list[CookieFinding] = []
    findings: list[Finding] = []

    for raw in cookie_headers:
        cookie = parse_cookie_header(raw)
        cookies.append(cookie)
        name = cookie.name

        # 1. Secure Flag check
        if not cookie.secure:
            findings.append(
                Finding(
                    id="SEC-CK-NO-SECURE",
                    title=f"Cookie '{name}' Missing 'Secure' Attribute",
                    category=Category.COOKIES,
                    severity=Severity.HIGH if is_https else Severity.MEDIUM,
                    description=(
                        f"The cookie '{name}' does not include the 'Secure' flag. Without it, "
                        "browsers may transmit this cookie over unencrypted HTTP channels."
                    ),
                    evidence=f"Set-Cookie: {raw}",
                    recommendation=f"Add '; Secure' to the Set-Cookie directive for '{name}'.",
                    cwe_id="CWE-614",
                )
            )

        # 2. HttpOnly Flag check
        if not cookie.httponly:
            findings.append(
                Finding(
                    id="SEC-CK-NO-HTTPONLY",
                    title=f"Cookie '{name}' Missing 'HttpOnly' Attribute",
                    category=Category.COOKIES,
                    severity=Severity.MEDIUM,
                    description=(
                        f"The cookie '{name}' lacks the 'HttpOnly' flag, leaving it accessible "
                        "to client-side scripts via document.cookie and vulnerable to XSS theft."
                    ),
                    evidence=f"Set-Cookie: {raw}",
                    recommendation=f"Add '; HttpOnly' to the Set-Cookie directive for '{name}'.",
                    cwe_id="CWE-1004",
                )
            )

        # 3. SameSite Attribute check
        if not cookie.samesite:
            findings.append(
                Finding(
                    id="SEC-CK-NO-SAMESITE",
                    title=f"Cookie '{name}' Missing 'SameSite' Attribute",
                    category=Category.COOKIES,
                    severity=Severity.MEDIUM,
                    description=(
                        f"The cookie '{name}' does not specify a SameSite attribute. "
                        "Without an explicit policy, cross-site requests may leak context (CSRF)."
                    ),
                    evidence=f"Set-Cookie: {raw}",
                    recommendation=f"Set 'SameSite=Strict' or 'SameSite=Lax' on cookie '{name}'.",
                    cwe_id="CWE-1275",
                )
            )
        else:
            samesite_upper = cookie.samesite.upper()
            if samesite_upper == "NONE":
                if not cookie.secure:
                    findings.append(
                        Finding(
                            id="SEC-CK-SAMESITE-NONE-INSECURE",
                            title=f"Cookie '{name}' SameSite=None Without Secure Flag",
                            category=Category.COOKIES,
                            severity=Severity.HIGH,
                            description=(
                                f"Cookie '{name}' sets SameSite=None without Secure attribute. "
                                "Modern browsers reject this configuration entirely."
                            ),
                            evidence=f"Set-Cookie: {raw}",
                            recommendation=(
                                f"Ensure '; Secure' is set whenever SameSite=None is used on "
                                f"'{name}'."
                            ),
                            cwe_id="CWE-614",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            id="SEC-CK-SAMESITE-NONE",
                            title=f"Cookie '{name}' Uses SameSite=None",
                            category=Category.COOKIES,
                            severity=Severity.LOW,
                            description=(
                                f"Cookie '{name}' allows cross-site inclusion (SameSite=None). "
                                "Ensure this cookie does not grant privileged access."
                            ),
                            evidence=f"Set-Cookie: {raw}",
                            recommendation="Consider 'SameSite=Lax' for sensitive cookies.",
                            cwe_id="CWE-352",
                        )
                    )

        # 4. Cookie prefix compliance
        if name.startswith("__Host-"):
            if not cookie.secure or cookie.domain is not None or cookie.path != "/":
                findings.append(
                    Finding(
                        id="SEC-CK-HOST-PREFIX-VIOLATION",
                        title=f"Cookie '{name}' Violates __Host- Prefix Specification",
                        category=Category.COOKIES,
                        severity=Severity.HIGH,
                        description=(
                            f"The cookie '{name}' utilizes '__Host-' prefix but violates RFC "
                            "6265bis: it must have Secure, Path=/, and omit the Domain attribute."
                        ),
                        evidence=f"Set-Cookie: {raw}",
                        recommendation=(
                            "Set '; Secure; Path=/' and remove any '; Domain=...' directive."
                        ),
                        cwe_id="CWE-614",
                    )
                )

        elif name.startswith("__Secure-") and not cookie.secure:
            findings.append(
                Finding(
                    id="SEC-CK-SECURE-PREFIX-VIOLATION",
                    title=f"Cookie '{name}' Violates __Secure- Prefix Specification",
                    category=Category.COOKIES,
                    severity=Severity.HIGH,
                    description=(
                        f"Cookie '{name}' uses '__Secure-' prefix but omits the Secure attribute."
                    ),
                    evidence=f"Set-Cookie: {raw}",
                    recommendation=f"Add '; Secure' to '{name}'.",
                    cwe_id="CWE-614",
                )
            )

    return cookies, findings
