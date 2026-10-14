"""Инфраструктурные проверки: TLS, DNS, RDAP, почтовая аутентификация, CMS.

Проверки:
- ssl_cert      — валидность TLS-сертификата: издатель, SAN, срок действия
- dns_records   — A, AAAA, NS, MX, TXT, CAA для регистрируемого домена
- reverse_dns   — PTR-записи для A-записей
- whois_rdap    — данные регистратора и сроки регистрации через RDAP
- email_auth    — SPF, DMARC, DKIM, MX
- cms_detect    — определение CMS по заголовкам/HTML и проверка открытых путей

Чистая логика разбора вынесена в синхронные функции без сети, поэтому её можно
покрывать юнит-тестами:
`parse_peer_cert`, `cert_days_left`, `host_matches_san`, `registrable_domain`,
`parse_spf`, `count_spf_lookups`, `parse_dmarc`, `parse_dkim`, `parse_rdap`,
`extract_meta_generator`, `detect_cms`.
"""
from __future__ import annotations

import asyncio
import email.utils
import re
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import dns.asyncresolver
import dns.reversename
from selectolax.lexbor import LexborHTMLParser

from app.core import AuditContext, CheckResult, Finding
from app.registry import check

CATEGORY = "Инфраструктура"

# Селекторы DKIM, которые имеет смысл проверять у популярных провайдеров.
DKIM_SELECTORS: List[str] = [
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "mail",
    "dkim",
    "s1",
    "s2",
    "mx",
]

# Доменные зоны второго уровня, где регистрируемый домен — три метки.
_MULTI_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "com.br", "net.br", "org.br",
    "co.in", "net.in", "org.in",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "co.za", "org.za",
    "com.tr", "com.ua", "co.kr", "com.mx", "co.il", "com.pl", "com.es",
    "com.hk", "com.sg", "com.tw", "co.th", "com.ar", "com.co",
}


# --------------------------------------------------------------------------- #
# Чистые функции: TLS-сертификат
# --------------------------------------------------------------------------- #
def _rdn_value(rdns: Any, key: str) -> Optional[str]:
    """Достать значение поля из структуры subject/issuer сертификата."""
    for rdn in rdns or ():
        for name, value in rdn:
            if name == key:
                return value
    return None


def _parse_not_after(value: Optional[str]) -> Optional[datetime]:
    """Разобрать дату в форматах ISO 8601 (RDAP) и RFC 2822 (сертификат)."""
    if not value:
        return None
    text = str(value).strip()
    # ISO 8601: 2015-01-01T00:00:00Z / 2015-01-01T00:00:00+00:00
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        pass
    # RFC 2822 / ASN.1: Dec 31 23:59:59 2030 GMT
    try:
        dt = email.utils.parsedate_to_datetime(text)
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        pass
    try:
        return datetime.fromtimestamp(ssl.cert_time_to_seconds(text), tz=timezone.utc)
    except Exception:
        return None


def cert_days_left(not_after: Optional[str]) -> Optional[int]:
    """Сколько полных дней остаётся до notAfter (отрицательное — уже истёк)."""
    dt = _parse_not_after(not_after)
    if dt is None:
        return None
    delta = dt - datetime.now(timezone.utc)
    return delta.days


def host_matches_san(names: List[str], host: str) -> bool:
    """Покрывает ли список SAN имя хоста (с поддержкой wildcard `*.domain`)."""
    if not names or not host:
        return False
    host = host.strip().lower().rstrip(".")
    for raw in names:
        name = (raw or "").strip().lower().rstrip(".")
        if not name:
            continue
        if name == host:
            return True
        if name.startswith("*."):
            suffix = name[2:]
            # wildcard покрывает ровно одну метку слева
            if host.endswith("." + suffix):
                prefix = host[: -(len(suffix) + 1)]
                if prefix and "." not in prefix:
                    return True
        # IP-адреса в SAN (iPAddress) здесь не разбираем: host всегда домен
    return False


def parse_peer_cert(cert: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Преобразовать результат ssl.getpeercert() в плоскую структуру."""
    if not cert:
        return {
            "issuer_org": None,
            "issuer_cn": None,
            "subject_cn": None,
            "san": [],
            "not_before": None,
            "not_after": None,
            "days_left": None,
            "serial": None,
        }
    san = [value for typ, value in cert.get("subjectAltName", ()) if typ == "DNS"]
    not_after = cert.get("notAfter")
    return {
        "issuer_org": _rdn_value(cert.get("issuer"), "organizationName"),
        "issuer_cn": _rdn_value(cert.get("issuer"), "commonName"),
        "subject_cn": _rdn_value(cert.get("subject"), "commonName"),
        "san": san,
        "not_before": cert.get("notBefore"),
        "not_after": not_after,
        "days_left": cert_days_left(not_after),
        "serial": cert.get("serialNumber"),
    }


async def fetch_ssl_certificate(
    host: str, port: int = 443, timeout: float = 15.0
) -> Optional[Dict[str, Any]]:
    """Установить TLS-соединение и прочитать сертификат. None при ошибке."""
    if not host:
        return None
    context = ssl.create_default_context()
    writer = None
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=context, server_hostname=host),
            timeout=timeout,
        )
    except Exception:
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass
        return None

    try:
        ssl_object = writer.get_extra_info("ssl_object")
        if ssl_object is None:
            return None
        cert = ssl_object.getpeercert()
        cipher = ssl_object.cipher()
        parsed = parse_peer_cert(cert)
        parsed["tls_version"] = ssl_object.version()
        parsed["cipher"] = cipher[0] if cipher else None
        return parsed
    except Exception:
        return None
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# Чистые функции: домены и DNS
# --------------------------------------------------------------------------- #
def registrable_domain(host: str) -> str:
    """Регистрируемый домен: убирает www и оставляет домен + зону."""
    host = (host or "").strip().lower()
    if not host:
        return ""
    host = host.split("/")[0].split(":")[0].strip(".")
    if host.startswith("www."):
        host = host[4:]
    parts = [p for p in host.split(".") if p]
    if len(parts) <= 2:
        return ".".join(parts)
    last_two = ".".join(parts[-2:])
    if last_two in _MULTI_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


def _resolver() -> "dns.asyncresolver.Resolver":
    resolver = dns.asyncresolver.Resolver(configure=True)
    resolver.search = []
    resolver.lifetime = 8.0
    resolver.timeout = 5.0
    return resolver


async def resolve_records(
    name: str, rdtype: str, lifetime: float = 8.0
) -> List[str]:
    """Вернуть список записей как текст. Пустой список при любой ошибке."""
    if not name:
        return []
    resolver = _resolver()
    try:
        answer = await resolver.resolve(name, rdtype, lifetime=lifetime, raise_on_no_answer=False)
    except Exception:
        return []
    if answer.rrset is None:
        return []
    out: List[str] = []
    for rdata in answer:
        try:
            out.append(rdata.to_text())
        except Exception:
            out.append(str(rdata))
    return out


# --------------------------------------------------------------------------- #
# Чистые функции: SPF / DMARC / DKIM
# --------------------------------------------------------------------------- #
def count_spf_lookups(spf_text: str) -> Dict[str, int]:
    """Считать DNS-запросы (lookup) механизмов SPF согласно RFC 7208."""
    counts = {
        "include": 0,
        "a": 0,
        "mx": 0,
        "ptr": 0,
        "exists": 0,
        "redirect": 0,
    }
    if not spf_text:
        return counts
    for token in spf_text.split():
        token = token.strip()
        if not token:
            continue
        # отбрасываем квалификатор (+ - ~ ?)
        if token[0] in "+-~?":
            token = token[1:]
        low = token.lower()
        if low.startswith("include:"):
            counts["include"] += 1
        elif low.startswith("exists:"):
            counts["exists"] += 1
        elif low.startswith("redirect="):
            counts["redirect"] += 1
        elif low == "a" or low.startswith("a:") or low.startswith("a/"):
            counts["a"] += 1
        elif low == "mx" or low.startswith("mx:") or low.startswith("mx/"):
            counts["mx"] += 1
        elif low == "ptr" or low.startswith("ptr:"):
            counts["ptr"] += 1
        # ip4:, ip6:, all — без DNS-запросов
    return counts


def parse_spf(records: List[str]) -> Dict[str, Any]:
    """Разобрать TXT-записи домена и выделить SPF.

    Возвращает присутствие, сам рекорд, квалификатор и число DNS-lookup.
    """
    spf_records: List[str] = []
    for raw in records or []:
        text = (raw or "").strip().strip('"').strip()
        if text.lower().startswith("v=spf1"):
            spf_records.append(text)

    if not spf_records:
        return {
            "present": False,
            "record": None,
            "count": 0,
            "multiple": False,
            "qualifier": None,
            "lookups": 0,
            "lookup_breakdown": count_spf_lookups(""),
        }

    record = spf_records[0]
    qualifier = None
    for token in record.split():
        tok = token.strip()
        if tok and tok[0] in "+-~?" and tok[1:].lower() == "all":
            qualifier = tok.lower()
            break
    lookups = count_spf_lookups(record)
    return {
        "present": True,
        "record": record,
        "count": len(spf_records),
        "multiple": len(spf_records) > 1,
        "qualifier": qualifier,
        "lookups": sum(lookups.values()),
        "lookup_breakdown": lookups,
    }


def parse_dmarc(records: List[str]) -> Dict[str, Any]:
    """Разобрать TXT-записи _dmarc-домена."""
    dmarc_record: Optional[str] = None
    for raw in records or []:
        text = (raw or "").strip().strip('"').strip()
        if text.lower().startswith("v=dmarc1"):
            dmarc_record = text
            break

    if dmarc_record is None:
        return {
            "present": False,
            "record": None,
            "policy": None,
            "subdomain_policy": None,
            "pct": None,
            "rua": None,
            "ruf": None,
        }

    tags: Dict[str, str] = {}
    for part in dmarc_record.split(";"):
        if "=" in part:
            key, _, value = part.partition("=")
            tags[key.strip().lower()] = value.strip()

    return {
        "present": True,
        "record": dmarc_record,
        "policy": (tags.get("p") or "").lower() or None,
        "subdomain_policy": (tags.get("sp") or "").lower() or None,
        "pct": tags.get("pct"),
        "rua": tags.get("rua"),
        "ruf": tags.get("ruf"),
    }


def parse_dkim(records: List[str]) -> Dict[str, Any]:
    """Есть ли в TXT-записях селектора корректная DKIM-запись."""
    for raw in records or []:
        text = (raw or "").strip().strip('"').strip()
        low = text.lower()
        if low.startswith("v=dkim1") or ("p=" in low and ("k=" in low or low.startswith("v="))):
            if "p=" in low:
                return {"present": True, "record": text[:200]}
    return {"present": False, "record": None}


# --------------------------------------------------------------------------- #
# Чистые функции: RDAP
# --------------------------------------------------------------------------- #
def _vcard_fn(entity: Dict[str, Any]) -> Optional[str]:
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return None
    for item in vcard[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
            return str(item[3])
    return None


def parse_rdap(data: Any) -> Dict[str, Any]:
    """Разобрать ответ RDAP: регистратор и ключевые события."""
    if not isinstance(data, dict):
        return {
            "registrar": None,
            "events": {},
            "registration": None,
            "expiration": None,
            "last_changed": None,
            "status": [],
            "nameservers": [],
            "age_days": None,
            "days_to_expiry": None,
        }

    events: Dict[str, str] = {}
    for event in data.get("events", []) or []:
        if isinstance(event, dict) and event.get("eventAction"):
            events[str(event["eventAction"]).lower()] = event.get("eventDate")

    registrar = None
    for entity in data.get("entities", []) or []:
        if isinstance(entity, dict) and "registrar" in (entity.get("roles") or []):
            registrar = _vcard_fn(entity)
            if registrar is None and entity.get("handle"):
                registrar = str(entity.get("handle"))
            break

    nameservers: List[str] = []
    for ns in data.get("nameservers", []) or []:
        if isinstance(ns, dict) and ns.get("ldhName"):
            nameservers.append(str(ns["ldhName"]).lower())

    registration = events.get("registration")
    expiration = events.get("expiration")
    last_changed = events.get("last changed") or events.get("last changed ")

    age_days = None
    reg_dt = _parse_not_after(registration)
    if reg_dt is not None:
        age_days = (datetime.now(timezone.utc) - reg_dt).days

    days_to_expiry = None
    exp_dt = _parse_not_after(expiration)
    if exp_dt is not None:
        days_to_expiry = (exp_dt - datetime.now(timezone.utc)).days

    return {
        "registrar": registrar,
        "events": events,
        "registration": registration,
        "expiration": expiration,
        "last_changed": last_changed,
        "status": list(data.get("status", []) or []),
        "nameservers": nameservers,
        "age_days": age_days,
        "days_to_expiry": days_to_expiry,
    }


# --------------------------------------------------------------------------- #
# Чистые функции: определение CMS
# --------------------------------------------------------------------------- #
# (название, маркеры в HTML/заголовках, ключ для поиска версии)
_CMS_RULES: List[Tuple[str, List[str], Optional[str]]] = [
    ("WordPress", ["wp-content", "wp-includes", "/wp-json", "wp-emoji-release", "wp-block-"], "wordpress"),
    ("WooCommerce", ["woocommerce", "wc-block-", "wc_add_to_cart", "wc-cart-fragments"], None),
    ("Bitrix", ["/bitrix/", "bitrix24", "bitrix"], "bitrix"),
    ("Tilda", ["tildacdn.com", "t-records"], None),
    ("Shopify", ["cdn.shopify.com", "shopify", "shopify-features", "x-shopify-stage"], None),
    ("Joomla", ["/media/jui/", "joomla", "option=com_content", "/components/com_"], "joomla"),
    ("Drupal", ["drupal-settings-json", "sites/default/files", "drupal", "x-drupal-cache"], "drupal"),
    ("OpenCart", ["opencart", "catalog/view/theme", "route=common/home", "route=product/"], None),
    ("MODX", ["/assets/components/", "modx", "modx-"], "modx"),
    ("Wix", ["wixstatic", "wix.com", "x-wix-request-id", "parastorage"], None),
    ("Next.js", ["__next_data__", "/_next/static", "next.js"], "next.js"),
    ("Nuxt", ["__nuxt__", "/_nuxt/", "nuxt"], "nuxt"),
]


def extract_meta_generator(html: str) -> str:
    """Значение тега <meta name="generator"> (или пустая строка)."""
    if not html:
        return ""
    try:
        tree = LexborHTMLParser(html)
    except Exception:
        return ""
    for node in tree.css("meta"):
        name = (node.attributes.get("name") or "").lower()
        if name == "generator":
            return (node.attributes.get("content") or "").strip()
    return ""


def _extract_version(text: str, key: str) -> Optional[str]:
    if not text or not key:
        return None
    pattern = re.compile(
        re.escape(key) + r"[\s/_-]*v?(\d+(?:\.\d+){1,3})",
        re.IGNORECASE,
    )
    match = pattern.search(text)
    return match.group(1) if match else None


def detect_cms(
    headers: Optional[Dict[str, str]] = None,
    html: str = "",
    meta_generator: str = "",
) -> Dict[str, Any]:
    """Определить CMS/технологии по заголовкам, HTML и meta generator.

    Возвращает {"detected": [...], "primary": str|None, "technologies": [...]}.
    """
    headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    generator = meta_generator or extract_meta_generator(html)

    header_blob = " ".join(f"{k}:{v}" for k, v in headers.items())
    haystack = " ".join([(html or "").lower(), header_blob.lower(), generator.lower()])

    detected: List[Dict[str, Any]] = []
    for name, markers, version_key in _CMS_RULES:
        signals = [m for m in markers if m in haystack]
        if not signals:
            continue
        version = None
        if version_key:
            version = _extract_version(generator, version_key) or _extract_version(
                header_blob, version_key
            )
        detected.append({"name": name, "version": version, "signals": signals})

    technologies = [d["name"] for d in detected]
    primary = detected[0]["name"] if detected else None
    return {"detected": detected, "primary": primary, "technologies": technologies}


# --------------------------------------------------------------------------- #
# Проверка 1: TLS-сертификат
# --------------------------------------------------------------------------- #
@check(id="ssl_cert", title="TLS-сертификат", category=CATEGORY)
async def ssl_cert(ctx: AuditContext) -> CheckResult:
    check_id = "ssl_cert"
    title = "TLS-сертификат"
    host = ctx.host.split(":")[0]

    info = await fetch_ssl_certificate(host)
    if info is None:
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="warning",
            score=0,
            findings=[
                Finding(
                    level="warning",
                    text=f"Не удалось установить TLS-соединение с {host}:443 — сертификат не прочитан",
                    fix="Проверить, что сайт отвечает по HTTPS на 443-м порту и сертификат выдан доверенным удостоверяющим центром",
                    hours=1.0,
                )
            ],
            raw={"host": host, "error": "tls_connection_failed"},
        )

    days_left = info.get("days_left")
    san = info.get("san", [])
    matches = host_matches_san(san, host)

    findings: List[Finding] = []
    status = "ok"
    score = 100

    if not matches:
        status = "critical"
        score = 0
        findings.append(
            Finding(
                level="critical",
                text=f"Сертификат не покрывает домен {host} — браузеры покажут ошибку защиты",
                fix=f"Выпустить сертификат с {host} в списке SAN (Subject Alternative Name) и переустановить его на сервере",
                hours=2.0,
            )
        )

    if days_left is None:
        findings.append(
            Finding(level="warning", text="Не удалось определить срок действия сертификата", fix="Проверить сертификат вручную", hours=0.5)
        )
        status = "warning" if status == "ok" else status
        score = min(score, 70)
    elif days_left < 0:
        status = "critical"
        score = 0
        findings.append(
            Finding(
                level="critical",
                text=f"Срок действия сертификата истёк {abs(days_left)} дн. назад",
                fix="Срочно продлить сертификат и настроить автообновление (Let's Encrypt + certbot / ACME)",
                hours=1.0,
            )
        )
    elif days_left < 14:
        status = "critical"
        score = 0
        findings.append(
            Finding(
                level="critical",
                text=f"Сертификат истекает через {days_left} дн. (notAfter: {info.get('not_after')})",
                fix="Продлить сертификат сейчас и настроить автоматическое продление",
                hours=1.0,
            )
        )
    elif days_left < 30:
        if status == "ok":
            status = "warning"
            score = 60
        findings.append(
            Finding(
                level="warning",
                text=f"Сертификат истекает через {days_left} дн. — требуется продление",
                fix="Продлить сертификат и проверить автопродление (ACME-задача в cron)",
                hours=0.5,
            )
        )
    else:
        findings.append(
            Finding(
                level="ok",
                text=f"Сертификат действителен ещё {days_left} дн., покрывает {host}",
                fix="",
            )
        )

    if status != "critical" and matches is False:
        status = "critical"

    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status=status,
        score=score,
        findings=findings,
        raw={
            "host": host,
            "issuer_org": info.get("issuer_org"),
            "issuer_cn": info.get("issuer_cn"),
            "subject_cn": info.get("subject_cn"),
            "san": san,
            "not_before": info.get("not_before"),
            "not_after": info.get("not_after"),
            "days_left": days_left,
            "host_matches_san": matches,
            "tls_version": info.get("tls_version"),
            "cipher": info.get("cipher"),
        },
    )


# --------------------------------------------------------------------------- #
# Проверка 2: DNS-записи
# --------------------------------------------------------------------------- #
@check(id="dns_records", title="DNS-записи домена", category=CATEGORY)
async def dns_records(ctx: AuditContext) -> CheckResult:
    check_id = "dns_records"
    title = "DNS-записи домена"
    domain = registrable_domain(ctx.host)

    if not domain:
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="warning",
            score=0,
            findings=[Finding(level="warning", text="Не удалось определить домен из адреса сайта", fix="Проверить корректность URL", hours=0.25)],
            raw={"domain": domain},
        )

    a, aaaa, ns, mx, txt, caa = await asyncio.gather(
        resolve_records(domain, "A"),
        resolve_records(domain, "AAAA"),
        resolve_records(domain, "NS"),
        resolve_records(domain, "MX"),
        resolve_records(domain, "TXT"),
        resolve_records(domain, "CAA"),
    )

    findings: List[Finding] = []
    status = "ok"
    score = 100

    if not a:
        status = "critical"
        score = 0
        findings.append(
            Finding(
                level="critical",
                text=f"У домена {domain} нет A-записи — сайт не разрешается в IP-адрес",
                fix=f"Добавить A-запись для {domain}, указывающую на IP сервера",
                hours=1.0,
            )
        )
    else:
        findings.append(Finding(level="ok", text=f"A-записи: {', '.join(a[:5])}", fix=""))

    if not caa:
        if status == "ok":
            status = "warning"
            score = min(score, 70)
        findings.append(
            Finding(
                level="warning",
                text="Нет CAA-записи — любой удостоверяющий центр может выпустить сертификат для домена",
                fix=f'Добавить CAA-запись, например: 0 issue "letsencrypt.org" и 0 iodef "mailto:admin@{domain}"',
                hours=0.5,
            )
        )
    else:
        findings.append(Finding(level="ok", text=f"CAA-записи: {', '.join(caa[:5])}", fix=""))

    if not aaaa:
        findings.append(
            Finding(
                level="info",
                text="Нет AAAA-записи (IPv6) — сайт недоступен по IPv6",
                fix="По возможности добавить AAAA-запись и включить IPv6 на сервере",
                hours=1.0,
            )
        )

    if not ns:
        if status == "ok":
            status = "warning"
            score = min(score, 60)
        findings.append(
            Finding(level="warning", text="Не найдены NS-записи домена", fix="Проверить делегирование домена и NS-серверы у регистратора", hours=1.0)
        )

    if not mx:
        findings.append(
            Finding(
                level="info",
                text="Нет MX-записей — домен не принимает почту",
                fix="Если почта на домене нужна, добавить MX-записи почтового провайдера",
                hours=0.5,
            )
        )

    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status=status,
        score=score,
        findings=findings,
        raw={
            "domain": domain,
            "A": a,
            "AAAA": aaaa,
            "NS": ns,
            "MX": mx,
            "TXT": txt,
            "CAA": caa,
        },
    )


# --------------------------------------------------------------------------- #
# Проверка 3: обратный DNS (PTR)
# --------------------------------------------------------------------------- #
@check(id="reverse_dns", title="Обратный DNS (PTR) для A-записей", category=CATEGORY)
async def reverse_dns(ctx: AuditContext) -> CheckResult:
    check_id = "reverse_dns"
    title = "Обратный DNS (PTR) для A-записей"
    domain = registrable_domain(ctx.host)

    a_records = await resolve_records(domain, "A")
    if not a_records:
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="warning",
            score=0,
            findings=[
                Finding(
                    level="warning",
                    text=f"Нет A-записей у {domain} — PTR проверить не удалось",
                    fix="Сначала настроить A-запись домена, затем обратный DNS",
                    hours=1.0,
                )
            ],
            raw={"domain": domain, "ptr": {}},
        )

    resolver = _resolver()
    ptr: Dict[str, List[str]] = {}

    async def lookup(ip: str) -> Tuple[str, List[str]]:
        try:
            rev = dns.reversename.from_address(ip)
            answer = await resolver.resolve(str(rev), "PTR", lifetime=8.0, raise_on_no_answer=False)
        except Exception:
            return ip, []
        if answer.rrset is None:
            return ip, []
        names: List[str] = []
        for rdata in answer:
            try:
                names.append(rdata.to_text().rstrip("."))
            except Exception:
                names.append(str(rdata).rstrip("."))
        return ip, names

    results = await asyncio.gather(*[lookup(ip) for ip in a_records[:10]])
    for ip, names in results:
        ptr[ip] = names

    missing = [ip for ip, names in ptr.items() if not names]
    findings: List[Finding] = []

    if not missing:
        findings.append(
            Finding(level="ok", text=f"PTR-записи настроены для всех {len(ptr)} A-адресов", fix="")
        )
        status = "ok"
        score = 100
    else:
        status = "warning"
        score = max(0, 100 - 20 * len(missing))
        findings.append(
            Finding(
                level="warning",
                text="Нет PTR-записи для адресов: " + ", ".join(missing),
                fix="Настроить обратную зону (PTR) у хостинг-провайдера, чтобы IP указывал на домен",
                hours=2.0,
            )
        )
        for ip, names in ptr.items():
            if names:
                findings.append(Finding(level="ok", text=f"{ip} -> {', '.join(names)}", fix=""))

    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status=status,
        score=score,
        findings=findings,
        raw={"domain": domain, "A": a_records, "ptr": ptr, "missing": missing},
    )


# --------------------------------------------------------------------------- #
# Проверка 4: RDAP (аналог whois)
# --------------------------------------------------------------------------- #
@check(id="whois_rdap", title="Данные регистратора домена (RDAP)", category=CATEGORY)
async def whois_rdap(ctx: AuditContext) -> CheckResult:
    check_id = "whois_rdap"
    title = "Данные регистратора домена (RDAP)"
    domain = registrable_domain(ctx.host)
    url = f"https://rdap.org/domain/{domain}"

    if not domain:
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="skipped",
            score=0,
            findings=[Finding(level="info", text="Не удалось определить домен для RDAP-запроса", fix="", hours=0.0)],
            raw={"domain": domain, "url": url},
        )

    resp = await ctx.get(url, timeout=20.0)
    if resp is None:
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="warning",
            score=0,
            findings=[
                Finding(
                    level="warning",
                    text=f"Не удалось получить RDAP-данные для {domain} (сетевой сбой)",
                    fix="Повторить проверку позже или запросить данные у регистратора вручную",
                    hours=0.5,
                )
            ],
            raw={"domain": domain, "url": url, "error": "network"},
        )

    if resp.status_code >= 400:
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="warning",
            score=40,
            findings=[
                Finding(
                    level="warning",
                    text=f"RDAP вернул HTTP {resp.status_code} для {domain} — данные недоступны",
                    fix="Проверить домен и RDAP-сервис, при необходимости посмотреть данные у регистратора",
                    hours=0.5,
                )
            ],
            raw={"domain": domain, "url": url, "status": resp.status_code},
        )

    try:
        data = resp.json()
    except Exception:
        data = None

    info = parse_rdap(data)
    findings: List[Finding] = []
    status = "ok"
    score = 100

    if info["registrar"]:
        findings.append(Finding(level="ok", text=f"Регистратор: {info['registrar']}", fix=""))
    else:
        findings.append(
            Finding(level="info", text="Регистратор не указан в RDAP-ответе", fix="Уточнить регистратора в панели домена", hours=0.25)
        )

    if info["registration"]:
        age = info["age_days"]
        age_text = f", возраст {age} дн." if age is not None else ""
        findings.append(Finding(level="ok", text=f"Дата регистрации: {info['registration']}{age_text}", fix=""))
    else:
        status = "warning"
        score = min(score, 70)
        findings.append(
            Finding(level="warning", text="Дата регистрации не найдена в RDAP", fix="Проверить историю домена у регистратора", hours=0.5)
        )

    days_to_expiry = info["days_to_expiry"]
    if info["expiration"]:
        if days_to_expiry is not None and days_to_expiry < 0:
            status = "critical"
            score = 0
            findings.append(
                Finding(
                    level="critical",
                    text=f"Срок регистрации домена истёк ({info['expiration']})",
                    fix="Срочно продлить домен у регистратора, иначе сайт и почта перестанут работать",
                    hours=1.0,
                )
            )
        elif days_to_expiry is not None and days_to_expiry < 30:
            status = "warning"
            score = min(score, 60)
            findings.append(
                Finding(
                    level="warning",
                    text=f"Регистрация домена истекает через {days_to_expiry} дн. ({info['expiration']})",
                    fix="Продлить домен и включить авто-продление у регистратора",
                    hours=1.0,
                )
            )
        else:
            findings.append(
                Finding(
                    level="ok",
                    text=f"Дата окончания регистрации: {info['expiration']}"
                    + (f" (осталось {days_to_expiry} дн.)" if days_to_expiry is not None else ""),
                    fix="",
                )
            )
    else:
        findings.append(
            Finding(level="info", text="Дата окончания регистрации не найдена в RDAP", fix="Проверить срок продления домена", hours=0.25)
        )

    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status=status,
        score=score,
        findings=findings,
        raw={"domain": domain, "url": url, "status": resp.status_code, **info},
    )


# --------------------------------------------------------------------------- #
# Проверка 5: почтовая аутентификация
# --------------------------------------------------------------------------- #
@check(id="email_auth", title="Почтовая аутентификация (SPF/DMARC/DKIM/MX)", category=CATEGORY)
async def email_auth(ctx: AuditContext) -> CheckResult:
    check_id = "email_auth"
    title = "Почтовая аутентификация (SPF/DMARC/DKIM/MX)"
    domain = registrable_domain(ctx.host)

    if not domain:
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="warning",
            score=0,
            findings=[Finding(level="warning", text="Не удалось определить домен для проверки почты", fix="Проверить корректность URL", hours=0.25)],
            raw={"domain": domain},
        )

    root_txt, mx, dmarc_txt = await asyncio.gather(
        resolve_records(domain, "TXT"),
        resolve_records(domain, "MX"),
        resolve_records(f"_dmarc.{domain}", "TXT"),
    )

    spf = parse_spf(root_txt)
    dmarc = parse_dmarc(dmarc_txt)

    dkim_results: Dict[str, Any] = {}
    dkim_txts = await asyncio.gather(
        *[resolve_records(f"{sel}._domainkey.{domain}", "TXT") for sel in DKIM_SELECTORS]
    )
    for selector, records in zip(DKIM_SELECTORS, dkim_txts):
        parsed = parse_dkim(records)
        if parsed["present"]:
            dkim_results[selector] = parsed

    findings: List[Finding] = []
    status = "ok"
    score = 100

    # --- SPF ---
    if not spf["present"]:
        status = "critical"
        score = 0
        findings.append(
            Finding(
                level="critical",
                text=f"Нет SPF-записи у домена {domain} — письма уязвимы к подделке отправителя",
                fix=f'Добавить TXT-запись: "v=spf1 include:<ваш_провайдер> -all" в DNS домена {domain}',
                hours=2.0,
            )
        )
    else:
        if spf["multiple"]:
            status = "warning" if status == "ok" else status
            score = min(score, 70)
            findings.append(
                Finding(
                    level="warning",
                    text=f"Найдено несколько SPF-записей ({spf['count']}) — это недопустимо и ломает проверку",
                    fix="Оставить ровно одну SPF-запись, объединив include-механизмы",
                    hours=1.0,
                )
            )
        qualifier = spf["qualifier"]
        if qualifier not in ("-all", "~all"):
            status = "warning" if status == "ok" else status
            score = min(score, 60)
            findings.append(
                Finding(
                    level="warning",
                    text=f"SPF-запись не завершается -all/~all (квалификатор: {qualifier or 'отсутствует'}) — защита неполная",
                    fix="Завершить SPF-запись строгим квалификатором '-all' (или '~all')",
                    hours=1.0,
                )
            )
        if spf["lookups"] > 10:
            status = "warning" if status == "ok" else status
            score = min(score, 60)
            findings.append(
                Finding(
                    level="warning",
                    text=f"SPF выполняет {spf['lookups']} DNS-lookup — превышен лимит RFC 7208 (10)",
                    fix="Сократить число include/a/mx в SPF-записи, объединив провайдеров или используя макросы",
                    hours=2.0,
                )
            )
        if status == "ok":
            findings.append(
                Finding(level="ok", text=f"SPF настроен ({spf['lookups']} DNS-lookup, квалификатор {qualifier})", fix="")
            )

    # --- DMARC ---
    if not dmarc["present"]:
        status = "critical" if status in ("ok", "warning") else status
        score = 0 if status == "critical" else score
        findings.append(
            Finding(
                level="critical",
                text=f"Нет DMARC-записи (_dmarc.{domain}) — нет политики обработки поддельных писем",
                fix=f'Добавить TXT-запись _dmarc: "v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}; pct=100"',
                hours=2.0,
            )
        )
    else:
        policy = dmarc["policy"]
        if policy == "none":
            status = "warning" if status == "ok" else status
            score = min(score, 60)
            findings.append(
                Finding(
                    level="warning",
                    text="DMARC-политика p=none — письма только мониторятся, подделки не блокируются",
                    fix="После сбора отчётов перейти на p=quarantine, затем на p=reject",
                    hours=1.0,
                )
            )
        elif policy in ("quarantine", "reject"):
            findings.append(Finding(level="ok", text=f"DMARC настроен (p={policy})", fix=""))
        else:
            status = "warning" if status == "ok" else status
            score = min(score, 60)
            findings.append(
                Finding(
                    level="warning",
                    text="DMARC-запись есть, но политика p не задана корректно",
                    fix="Указать p=quarantine или p=reject в DMARC-записи",
                    hours=1.0,
                )
            )

    # --- DKIM ---
    if dkim_results:
        findings.append(
            Finding(
                level="ok",
                text="DKIM-записи найдены для селекторов: " + ", ".join(sorted(dkim_results)),
                fix="",
            )
        )
    else:
        if status == "ok":
            status = "warning"
            score = min(score, 70)
        findings.append(
            Finding(
                level="warning",
                text="DKIM-запись не найдена ни для одного из проверенных селекторов",
                fix="Настроить DKIM у почтового провайдера и опубликовать публичный ключ в TXT-записи <selector>._domainkey",
                hours=2.0,
            )
        )

    # --- MX ---
    if not mx:
        if status == "ok":
            status = "warning"
            score = min(score, 70)
        findings.append(
            Finding(
                level="warning",
                text="Нет MX-записей — домен не принимает почту, аутентификация отправителя неполна",
                fix="Добавить MX-записи почтового провайдера",
                hours=1.0,
            )
        )
    else:
        findings.append(Finding(level="ok", text=f"MX-записи: {', '.join(mx[:5])}", fix=""))

    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status=status,
        score=score,
        findings=findings,
        raw={
            "domain": domain,
            "spf": spf,
            "dmarc": dmarc,
            "dkim": {
                "selectors_checked": DKIM_SELECTORS,
                "found": sorted(dkim_results),
                "records": {k: v.get("record") for k, v in dkim_results.items()},
            },
            "mx": mx,
            "txt": root_txt,
        },
    )


# --------------------------------------------------------------------------- #
# Проверка 6: определение CMS
# --------------------------------------------------------------------------- #
@check(id="cms_detect", title="CMS и открытые служебные пути", category=CATEGORY)
async def cms_detect(ctx: AuditContext) -> CheckResult:
    check_id = "cms_detect"
    title = "CMS и открытые служебные пути"

    resp = await ctx.home()
    if resp is None:
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="warning",
            score=0,
            findings=[
                Finding(
                    level="warning",
                    text="Не удалось получить главную страницу для определения CMS",
                    fix="Проверить доступность сайта и повторить аудит",
                    hours=0.5,
                )
            ],
            raw={"url": ctx.url, "error": "network"},
        )

    html = resp.text or ""
    headers = dict(resp.headers)
    detection = detect_cms(headers=headers, html=html)
    technologies = detection["technologies"]

    findings: List[Finding] = []
    status = "ok"
    score = 100
    probes: Dict[str, Any] = {}

    if technologies:
        parts = []
        for item in detection["detected"]:
            parts.append(item["name"] + (f" {item['version']}" if item["version"] else ""))
        findings.append(Finding(level="info", text="Обнаружено: " + ", ".join(parts), fix=""))
    else:
        findings.append(
            Finding(level="info", text="CMS не определена по заголовкам и HTML", fix="", hours=0.0)
        )

    # --- Проверка открытых путей WordPress ---
    if "WordPress" in technologies:
        wp_paths = {
            "wp_json": ("/wp-json/", (200,)),
            "xmlrpc": ("/xmlrpc.php", (200, 405)),
            "readme": ("/readme.html", (200,)),
            "debug_log": ("/wp-content/debug.log", (200,)),
        }
        for key, (path, ok_codes) in wp_paths.items():
            r = await ctx.get(ctx.base + path, timeout=10.0)
            if r is None:
                probes[key] = {"path": path, "status": None}
                continue
            probes[key] = {"path": path, "status": r.status_code, "exposed": r.status_code in ok_codes}

        if probes.get("debug_log", {}).get("exposed"):
            status = "critical"
            score = 0
            findings.append(
                Finding(
                    level="critical",
                    text="Открыт файл /wp-content/debug.log — утечка отладочной информации и путей сервера",
                    fix="Удалить debug.log, отключить WP_DEBUG_LOG в wp-config.php и закрыть доступ к /wp-content через правила сервера",
                    hours=1.0,
                )
            )

        if probes.get("readme", {}).get("exposed"):
            if status == "ok":
                status = "warning"
                score = min(score, 70)
            findings.append(
                Finding(
                    level="warning",
                    text="Доступен /readme.html — раскрывается версия WordPress",
                    fix="Удалить/закрыть readme.html и не публиковать точную версию CMS",
                    hours=0.5,
                )
            )

        xmlrpc = probes.get("xmlrpc", {})
        if xmlrpc.get("exposed"):
            if status == "ok":
                status = "warning"
                score = min(score, 75)
            findings.append(
                Finding(
                    level="warning",
                    text="Доступен /xmlrpc.php (HTTP 200) — используется для брутфорса и DDoS-атак",
                    fix="Заблокировать /xmlrpc.php на уровне сервера, если он не нужен",
                    hours=0.5,
                )
            )

        if probes.get("wp_json", {}).get("exposed"):
            findings.append(
                Finding(
                    level="ok",
                    text="REST API /wp-json/ открыт (это нормально, но проверьте чувствительные эндпоинты)",
                    fix="",
                )
            )

    # --- Проверка открытой админки Bitrix ---
    if "Bitrix" in technologies:
        r = await ctx.get(ctx.base + "/bitrix/admin/", timeout=10.0)
        admin_status = r.status_code if r is not None else None
        probes["bitrix_admin"] = {"path": "/bitrix/admin/", "status": admin_status}
        if admin_status == 200:
            if status == "ok":
                status = "warning"
                score = min(score, 75)
            findings.append(
                Finding(
                    level="warning",
                    text="Открыт /bitrix/admin/ — страница входа в админку доступна извне",
                    fix="Ограничить доступ к /bitrix/admin/ по IP и включить двухфакторную аутентификацию",
                    hours=1.0,
                )
            )

    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status=status,
        score=score,
        findings=findings,
        raw={
            "url": ctx.url,
            "cms": technologies,
            "detected": detection["detected"],
            "primary": detection["primary"],
            "server": resp.headers.get("server"),
            "x_powered_by": resp.headers.get("x-powered-by"),
            "generator": extract_meta_generator(html),
            "probes": probes,
        },
    )
