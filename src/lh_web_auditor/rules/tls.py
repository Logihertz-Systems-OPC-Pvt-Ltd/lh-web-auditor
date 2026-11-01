"""TLS and transport layer security evaluation rules."""

from __future__ import annotations

from urllib.parse import urlparse

from lh_web_auditor.models import Category, Finding, Severity, TlsAuditResult


def evaluate_tls(
    target_url: str,
    final_url: str,
    status_code: int,
    http_version: str | None = None,
) -> tuple[TlsAuditResult, list[Finding]]:
    """Audit transport security, scheme enforcement, and HTTPS redirection.

    Args:
        target_url: The initial URL targeted by the scan.
        final_url: The final destination URL after redirects.
        status_code: HTTP response status code.
        http_version: Negotiated HTTP protocol version (e.g. HTTP/1.1, HTTP/2).

    Returns:
        A tuple of (TlsAuditResult, list of detected Finding objects).
    """
    parsed_target = urlparse(target_url)
    parsed_final = urlparse(final_url)

    target_is_https = parsed_target.scheme.lower() == "https"
    final_is_https = parsed_final.scheme.lower() == "https"
    redirects_to_https = (not target_is_https) and final_is_https

    findings: list[Finding] = []

    # Check for unencrypted HTTP without HTTPS redirection
    if not target_is_https and not redirects_to_https:
        findings.append(
            Finding(
                id="SEC-TLS-CLEARTEXT-HTTP",
                title="Endpoint Operates Over Cleartext HTTP Without Redirection",
                category=Category.TLS,
                severity=Severity.HIGH,
                description=(
                    "Target URL uses unencrypted HTTP and does not redirect to HTTPS. "
                    "Network traffic is vulnerable to eavesdropping and manipulation."
                ),
                evidence=(f"Target URL '{target_url}' resolved to non-HTTPS URL '{final_url}'."),
                recommendation="Configure permanent 301 or 308 redirects from HTTP to HTTPS.",
                cwe_id="CWE-319",
            )
        )
    elif redirects_to_https:
        findings.append(
            Finding(
                id="SEC-TLS-HTTP-REDIRECT-SUCCESS",
                title="HTTP Successfully Upgraded to HTTPS",
                category=Category.TLS,
                severity=Severity.INFO,
                description="Plain HTTP request was redirected to a secure HTTPS destination.",
                evidence=f"Redirected from {target_url} to {final_url}",
                recommendation="Maintain strict HTTP-to-HTTPS redirection rules.",
                cwe_id=None,
            )
        )

    tls_result = TlsAuditResult(
        scheme=parsed_final.scheme.lower(),
        is_https=final_is_https,
        redirects_to_https=redirects_to_https,
        http_version=http_version,
        status_code=status_code,
    )

    return tls_result, findings
