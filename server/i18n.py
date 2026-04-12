"""Internationalization support for labwatch."""

import json
from pathlib import Path
from typing import Optional

TRANSLATIONS_DIR = Path(__file__).parent / "translations"
SUPPORTED_LANGUAGES = ["en", "de", "uk", "fr", "es"]
DEFAULT_LANGUAGE = "en"

# Language display names (in their own language)
LANGUAGE_NAMES = {
    "en": "English",
    "de": "Deutsch",
    "uk": "\u0423\u043a\u0440\u0430\u0457\u043d\u0441\u044c\u043a\u0430",
    "fr": "Fran\u00e7ais",
    "es": "Espa\u00f1ol",
}

_cache: dict[str, dict[str, str]] = {}


def _load_translations(lang: str) -> dict[str, str]:
    """Load translations for a language, with English fallback."""
    if lang in _cache:
        return _cache[lang]

    # Always load English as base
    en_path = TRANSLATIONS_DIR / "en.json"
    base = {}
    if en_path.exists():
        base = json.loads(en_path.read_text(encoding="utf-8"))

    if lang == "en":
        _cache["en"] = base
        return base

    # Load target language and merge with English fallback
    lang_path = TRANSLATIONS_DIR / f"{lang}.json"
    if lang_path.exists():
        overlay = json.loads(lang_path.read_text(encoding="utf-8"))
        merged = {**base, **overlay}
    else:
        merged = base

    _cache[lang] = merged
    return merged


def get_translations(lang: Optional[str] = None) -> dict[str, str]:
    """Get translation dict for a language."""
    if not lang or lang not in SUPPORTED_LANGUAGES:
        lang = DEFAULT_LANGUAGE
    return _load_translations(lang)


def detect_language(request) -> str:
    """Detect language from request (query param > cookie > Accept-Language header)."""
    # 1. Query param ?lang=de
    lang = request.query_params.get("lang", "").lower()
    if lang in SUPPORTED_LANGUAGES:
        return lang

    # 2. Cookie
    lang = request.cookies.get("labwatch_lang", "").lower()
    if lang in SUPPORTED_LANGUAGES:
        return lang

    # 3. Accept-Language header
    accept = request.headers.get("accept-language", "")
    for part in accept.split(","):
        code = part.split(";")[0].strip().split("-")[0].lower()
        if code in SUPPORTED_LANGUAGES:
            return code

    return DEFAULT_LANGUAGE


def reload_translations():
    """Clear cache and reload all translations."""
    _cache.clear()
