"""Asynchronous web configuration auditing engine using httpx."""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime
from urllib.parse import urlparse

import httpx

from lh_web_auditor.models import (
    BatchResult,
    Category,
    Finding,
    ScanResult,
    Severity,
)
from lh_web_auditor.rules.cookies import evaluate_cookies
from lh_web_auditor.rules.cors import evaluate_cors_response
from lh_web_auditor.rules.headers import evaluate_headers
from lh_web_auditor.rules.tls import evaluate_tls
from lh_web_auditor.scoring import calculate_score

_DEFAULT_PROBE_ORIGIN = "https://evil-attacker.example.com"


class WebAuditor:
    """Core asynchronous security configuration auditor."""

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = "lh-web-auditor/0.1.0",
        follow_redirects: bool = True,
        verify_ssl: bool = True,
    ) -> None:
        """Initialize the WebAuditor instance.

        Args:
            timeout: Network request timeout in seconds.
            user_agent: Custom User-Agent header string.
            follow_redirects: Whether to follow HTTP redirection chains.
            verify_ssl: Whether to verify SSL/TLS certificates.
        """
        self.timeout = timeout
        self.user_agent = user_agent
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl

    @staticmethod
    def normalize_url(url: str) -> str:
        """Ensure the URL has an explicit scheme, defaulting to https://."""
        stripped = url.strip()
        if not stripped.startswith(("http://", "https://")):
            return f"https://{stripped}"
        return stripped

    async def _probe_cors(self, client: httpx.AsyncClient, url: str) -> tuple[dict[str, str], int]:
        """Send a safe preflight request to detect CORS reflection or wildcard policies."""
        headers = {
            "Origin": _DEFAULT_PROBE_ORIGIN,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "X-Audit-Probe",
            "User-Agent": self.user_agent,
        }
        try:
            # First attempt standard preflight OPTIONS
            resp = await client.options(url, headers=headers)
            if resp.status_code in (200, 204):
                return dict(resp.headers), resp.status_code

            # Fallback to simple GET with Origin header if OPTIONS is not handled
            resp_get = await client.get(
                url,
                headers={"Origin": _DEFAULT_PROBE_ORIGIN, "User-Agent": self.user_agent},
            )
            return dict(resp_get.headers), resp_get.status_code
        except Exception:
            return {}, 0

    async def scan(self, url: str) -> ScanResult:
        """Perform an asynchronous audit on a single target URL.

        Args:
            url: The target web address to audit.

        Returns:
            A populated ScanResult instance with score, grade, and findings.
        """
        target_url = self.normalize_url(url)
        timestamp = datetime.now(UTC).isoformat()
        start_time = time.perf_counter()

        client_kwargs = {
            "timeout": self.timeout,
            "follow_redirects": self.follow_redirects,
            "verify": self.verify_ssl,
            "headers": {"User-Agent": self.user_agent},
        }

        try:
            async with httpx.AsyncClient(**client_kwargs) as client:
                response = await client.get(target_url)
                response_time_ms = (time.perf_counter() - start_time) * 1000.0

                final_url = str(response.url)
                status_code = response.status_code
                response_headers = dict(response.headers)
                cookie_headers = response.headers.get_list("set-cookie")

                # Probe CORS behavior
                cors_headers, cors_status = await self._probe_cors(client, target_url)

                # Determine transport details
                is_https = urlparse(final_url).scheme.lower() == "https"
                http_version = response.http_version

                # Run evaluation rules
                findings: list[Finding] = []

                # 1. Headers
                findings.extend(evaluate_headers(response_headers, is_https=is_https))

                # 2. Cookies
                cookies, cookie_findings = evaluate_cookies(cookie_headers, is_https=is_https)
                findings.extend(cookie_findings)

                # 3. CORS
                cors_probe, cors_findings = evaluate_cors_response(
                    cors_headers,
                    tested_origin=_DEFAULT_PROBE_ORIGIN,
                    status_code=cors_status,
                )
                findings.extend(cors_findings)

                # 4. TLS & Transport
                tls_result, tls_findings = evaluate_tls(
                    target_url=target_url,
                    final_url=final_url,
                    status_code=status_code,
                    http_version=http_version,
                )
                findings.extend(tls_findings)

                # Calculate final numerical score and grade
                score, grade = calculate_score(findings)

                return ScanResult(
                    target_url=target_url,
                    final_url=final_url,
                    status_code=status_code,
                    response_time_ms=response_time_ms,
                    timestamp=timestamp,
                    headers=response_headers,
                    findings=findings,
                    score=score,
                    grade=grade,
                    cookies=cookies,
                    cors=cors_probe,
                    tls=tls_result,
                    error=None,
                )

        except Exception as exc:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            error_message = f"{type(exc).__name__}: {exc}"
            conn_finding = Finding(
                id="SEC-CONN-ERROR",
                title="Target Connection or Resolution Failed",
                category=Category.TLS,
                severity=Severity.HIGH,
                description=f"The auditor could not establish a connection to '{target_url}'.",
                evidence=error_message,
                recommendation="Verify target network availability, DNS, and firewalls.",
                cwe_id=None,
            )
            return ScanResult(
                target_url=target_url,
                final_url=target_url,
                status_code=0,
                response_time_ms=duration_ms,
                timestamp=timestamp,
                headers={},
                findings=[conn_finding],
                score=0,
                grade="F",
                cookies=[],
                cors=None,
                tls=None,
                error=error_message,
            )

    async def scan_batch(self, urls: list[str], concurrency: int = 5) -> BatchResult:
        """Concurrently audit multiple target URLs with bounded concurrency.

        Args:
            urls: List of URL strings to audit.
            concurrency: Maximum number of simultaneous network requests.

        Returns:
            BatchResult containing all individual ScanResults and summary statistics.
        """
        semaphore = asyncio.Semaphore(concurrency)
        timestamp = datetime.now(UTC).isoformat()

        async def _worker(url: str) -> ScanResult:
            async with semaphore:
                return await self.scan(url)

        tasks = [_worker(u) for u in urls if u.strip() and not u.strip().startswith("#")]
        if not tasks:
            return BatchResult(
                timestamp=timestamp,
                total_scanned=0,
                average_score=0.0,
                results=[],
            )

        results = await asyncio.gather(*tasks)
        successful = [r for r in results if r.is_successful]
        avg_score = sum(r.score for r in successful) / len(successful) if successful else 0.0

        return BatchResult(
            timestamp=timestamp,
            total_scanned=len(results),
            average_score=avg_score,
            results=list(results),
        )
