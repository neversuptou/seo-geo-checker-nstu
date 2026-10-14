from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urljoin, urlparse, urlunparse

import httpx
from selectolax.lexbor import LexborHTMLParser as HTMLParser

BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"


@dataclass
class Finding:
    level: str  # critical|warning|info|ok
    text: str
    fix: str = ""
    hours: float = 0.0


@dataclass
class CheckResult:
    id: str
    title: str
    category: str
    status: str  # ok|warning|critical|error|skipped
    score: int  # 0..100
    findings: List[Finding]
    raw: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "status": self.status,
            "score": self.score,
            "findings": [asdict(f) for f in self.findings],
            "raw": self.raw,
        }


def _bare_host(host: str) -> str:
    host = (host or "").lower()
    return host[4:] if host.startswith("www.") else host


class ThrottledTransport(httpx.AsyncBaseTransport):
    """Ограничивает параллельные запросы и повторяет запрос при сетевом сбое/429/503.

    Сайты на shared-хостинге начинают рвать соединения, если проверки бьют
    в них десятками параллельных запросов — без этого получаются ложные «битые ссылки».
    """

    RETRY_STATUSES = {429, 503}

    def __init__(
        self,
        inner: httpx.AsyncBaseTransport | None = None,
        limit: int = 6,
        retries: int = 2,
        paced_host: str | None = None,
        min_interval: float = 0.0,
    ) -> None:
        self._inner = inner or httpx.AsyncHTTPTransport()
        self._sem = asyncio.Semaphore(limit)
        self._retries = retries
        # Бережный режим: запросы к проверяемому сайту идут строго по одному с паузой,
        # чтобы не сработала антибот-защита (Imunify360, Cloudflare). Внешние сервисы не тормозим.
        self._paced_host = _bare_host(paced_host) if paced_host else None
        self._min_interval = min_interval
        self._pace_lock = asyncio.Lock()
        self._last_request = 0.0

    async def _pace(self, request: httpx.Request) -> None:
        if not self._paced_host or _bare_host(request.url.host) != self._paced_host:
            return
        async with self._pace_lock:
            loop = asyncio.get_running_loop()
            wait = self._last_request + self._min_interval - loop.time()
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request = loop.time()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        for attempt in range(self._retries + 1):
            last = attempt == self._retries
            await self._pace(request)
            async with self._sem:
                try:
                    resp = await self._inner.handle_async_request(request)
                except (httpx.TransportError,) :
                    if last:
                        raise
                    resp = None
            if resp is not None and (resp.status_code not in self.RETRY_STATUSES or last):
                return resp
            if resp is not None:
                await resp.aclose()
            await asyncio.sleep(1.5 * (attempt + 1))
        raise httpx.ConnectError("retries exhausted", request=request)

    async def aclose(self) -> None:
        await self._inner.aclose()


class AuditContext:
    def __init__(
        self,
        url: str,
        keywords: List[str] | None = None,
        client: httpx.AsyncClient | None = None,
        gentle: bool = False,
    ) -> None:
        self.gentle = gentle
        self.keywords = keywords or []
        self._cache: Dict[str, httpx.Response] = {}
        self._lock = asyncio.Lock()

        # Normalize URL
        parsed = urlparse(url.strip() if url else "")
        if not parsed.scheme:
            url_norm = "https://" + url.strip()
            parsed = urlparse(url_norm)
        else:
            url_norm = urlunparse(parsed._replace(fragment=""))

        # Ensure scheme is https if http? but requirement says add https if missing; keep scheme
        if parsed.scheme not in ("http", "https"):
            url_norm = "https://" + url.strip()
            parsed = urlparse(url_norm)

        self.url = url_norm.rstrip("/")
        parsed_base = urlparse(self.url)
        self.base = f"{parsed_base.scheme}://{parsed_base.netloc}"
        self.host = parsed_base.netloc
        self.client = client

    def _cache_key(self, url: str, **kw: Any) -> str:
        # Simple key by url and relevant headers if any
        headers = kw.get("headers") or {}
        key_parts = [url]
        for k in sorted(headers.keys()):
            key_parts.append(f"{k}:{headers[k]}")
        params = kw.get("params") or {}
        for k in sorted(params):
            key_parts.append(f"?{k}={params[k]}")
        # Без этого GET и HEAD-подобные запросы с разными редиректами делили бы кэш
        key_parts.append(f"redirects:{kw.get('follow_redirects')}")
        return hashlib.md5("|".join(key_parts).encode()).hexdigest()

    async def get(self, url: str, **kw: Any) -> httpx.Response | None:
        follow_redirects = kw.pop("follow_redirects", True)
        timeout = kw.pop("timeout", 15.0)
        headers = kw.pop("headers", None)
        req_kw: Dict[str, Any] = {"follow_redirects": follow_redirects, "timeout": timeout}
        if headers:
            req_kw["headers"] = headers
        params = kw.pop("params", None)
        if params:
            req_kw["params"] = params
        cache_key = self._cache_key(url, **req_kw)
        async with self._lock:
            if cache_key in self._cache:
                return self._cache[cache_key]
        try:
            resp = await self.client.get(url, **req_kw) if self.client else None
        except Exception:
            return None
        if resp is not None:
            async with self._lock:
                self._cache[cache_key] = resp
        return resp

    async def home(self) -> httpx.Response | None:
        return await self.get(self.url)

    async def home_tree(self) -> HTMLParser | None:
        resp = await self.home()
        if resp is None:
            return None
        try:
            return HTMLParser(resp.text)
        except Exception:
            return None
