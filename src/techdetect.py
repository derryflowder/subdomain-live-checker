"""Detect technologies and versions from HTTP headers and HTML source."""
from __future__ import annotations

import re

from src.models import TechDetection

# (header, tech_name, regex, category)
_HEADER_RULES: list[tuple[str, str, re.Pattern[str], str]] = [
    ("server", "nginx", re.compile(r"nginx(?:/([\d.]+))?", re.I), "server"),
    ("server", "Apache", re.compile(r"Apache(?:/([\d.]+))?", re.I), "server"),
    ("server", "IIS", re.compile(r"Microsoft-IIS/([\d.]+)", re.I), "server"),
    ("server", "LiteSpeed", re.compile(r"LiteSpeed", re.I), "server"),
    ("server", "Caddy", re.compile(r"Caddy(?:/([\d.]+))?", re.I), "server"),
    ("server", "OpenResty", re.compile(r"openresty(?:/([\d.]+))?", re.I), "server"),
    ("x-powered-by", "PHP", re.compile(r"PHP/([\d.]+)", re.I), "backend"),
    ("x-powered-by", "ASP.NET", re.compile(r"ASP\.NET", re.I), "backend"),
    ("x-powered-by", "Express", re.compile(r"Express", re.I), "backend"),
    ("x-powered-by", "Next.js", re.compile(r"Next\.js\s*([\d.]+)?", re.I), "framework"),
    ("x-aspnet-version", "ASP.NET", re.compile(r"([\d.]+)"), "backend"),
    ("x-drupal-cache", "Drupal", re.compile(r".+"), "cms"),
    ("x-shopify-stage", "Shopify", re.compile(r".+"), "platform"),
    ("x-vercel-id", "Vercel", re.compile(r".+"), "platform"),
    ("via", "Varnish", re.compile(r"varnish", re.I), "cdn"),
    ("x-served-by", "Fastly", re.compile(r"cache-", re.I), "cdn"),
]

_GENERATOR_PATTERNS = [
    re.compile(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']', re.I),
    re.compile(r'<meta\s+content=["\']([^"\']+)["\']\s+name=["\']generator["\']', re.I),
]

# (tech_name, regex, category)
_HTML_RULES: list[tuple[str, re.Pattern[str], str]] = [
    ("WordPress", re.compile(r'/wp-(?:content|includes)/', re.I), "cms"),
    ("WordPress", re.compile(r'wp-json', re.I), "cms"),
    ("Drupal", re.compile(r'/sites/(?:default|all)/', re.I), "cms"),
    ("Joomla", re.compile(r'/media/system/js/', re.I), "cms"),
    ("jQuery", re.compile(r'jquery[.-]([\d.]+)(?:\.min)?\.js', re.I), "library"),
    ("Bootstrap", re.compile(r'bootstrap[./]([\d.]+)', re.I), "library"),
    ("Vue.js", re.compile(r'vue[@/]([\d.]+)', re.I), "framework"),
    ("React", re.compile(r'react[@/]([\d.]+)?', re.I), "framework"),
    ("Angular", re.compile(r'ng-version=["\']([^"\']+)["\']', re.I), "framework"),
    ("Next.js", re.compile(r'__NEXT_DATA__', re.I), "framework"),
    ("Nuxt", re.compile(r'__NUXT__', re.I), "framework"),
    ("Google Analytics", re.compile(r'(?:gtag|googletagmanager|analytics\.js)', re.I), "analytics"),
    ("Cloudflare CDN", re.compile(r'cdnjs\.cloudflare\.com', re.I), "cdn"),
    ("Font Awesome", re.compile(r'font-?awesome[/.]([\d.]+)', re.I), "library"),
]

_CMS_KEYWORDS = ("wordpress", "drupal", "joomla", "shopify", "ghost")


def _add(
    findings: dict[str, TechDetection],
    name: str,
    version: str | None,
    category: str,
) -> None:
    existing = findings.get(name)
    if existing is not None:
        if existing.version or not version:
            return
    findings[name] = TechDetection(name=name, version=version, category=category)


def detect_technologies(
    html: str,
    headers: dict[str, str] | None = None,
) -> list[TechDetection]:
    findings: dict[str, TechDetection] = {}

    if headers:
        lower = {k.lower(): v for k, v in headers.items()}
        for header_name, tech_name, pattern, category in _HEADER_RULES:
            value = lower.get(header_name)
            if not value:
                continue
            match = pattern.search(value)
            if not match:
                continue
            version = match.group(1) if match.groups() else None
            _add(findings, tech_name, version, category)

    for pattern in _GENERATOR_PATTERNS:
        for match in pattern.finditer(html):
            content = match.group(1).strip()
            if not content:
                continue
            parts = content.split()
            name = parts[0]
            version = parts[1] if len(parts) > 1 else None
            is_cms = any(k in name.lower() for k in _CMS_KEYWORDS)
            category = "cms" if is_cms else "generator"
            _add(findings, name, version, category)

    for tech_name, pattern, category in _HTML_RULES:
        match = pattern.search(html)
        if not match:
            continue
        version = match.group(1) if match.groups() else None
        _add(findings, tech_name, version, category)

    return list(findings.values())