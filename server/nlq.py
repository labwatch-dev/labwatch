"""Natural language query engine for labwatch.

Parses common infrastructure questions and answers them from metrics data.
No LLM required — uses regex pattern matching and template responses.
"""

import logging
import re
import sqlite3
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import database as db
from nlq_templates import TEMPLATES

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# User scoping (multi-tenant safety)
# ---------------------------------------------------------------------------
#
# When query() is called with an email, all lab lookups are scoped to that
# user via _scoped_list_labs(). This prevents a user querying through the
# MCP "ask" tool from seeing hosts owned by other users.
#
# When query() is called with email=None (admin / global), the scope is
# unset and lookups return all labs as before.
# ---------------------------------------------------------------------------

_scope_email: ContextVar[Optional[str]] = ContextVar("_nlq_scope_email", default=None)


# ---------------------------------------------------------------------------
# Locale-aware response templates (Phase 2 multilingual)
# ---------------------------------------------------------------------------
#
# `_nlq_locale` is set by query() from the `lang` argument (which the web
# endpoint derives from query-string / cookie / Accept-Language via
# i18n.detect_language). Handlers call `_t(key, **kwargs)` to look up a
# localized template string and format it with named placeholders.
#
# Unknown keys fall back to English. Unknown languages fall back to English.
# Missing placeholders silently return the unformatted template rather than
# blowing up a response mid-render.
# ---------------------------------------------------------------------------

_nlq_locale: ContextVar[str] = ContextVar("_nlq_locale", default="en")


def _t(key: str, **kwargs: Any) -> str:
    """Look up a localized NLQ response template and format it.

    Falls back to English on missing key or unknown locale. Returns the raw
    template if `.format()` raises (missing placeholder), so a template bug
    never produces a 500 — the user just sees the unsubstituted string.
    """
    lang = _nlq_locale.get()
    catalog = TEMPLATES.get(lang) or TEMPLATES["en"]
    template = catalog.get(key)
    if template is None:
        template = TEMPLATES["en"].get(key, key)
    if not kwargs:
        return template
    try:
        return template.format(**kwargs)
    except (KeyError, IndexError, ValueError):
        return template


# ---------------------------------------------------------------------------
# Typo normalization
# ---------------------------------------------------------------------------
#
# Common misspellings of core NLQ keywords. Substituted whole-word before
# pattern matching so 'stautus of fleet' / 'memry usage' route correctly
# instead of falling through to the fallback handler.
#
# Only includes typos that have ZERO meaning in our domain — e.g. 'stautus'
# is never a real word. Ambiguous corrections (e.g. 'cup' -> 'cpu', 'feet'
# -> 'fleet') are intentionally omitted to avoid false positives.
# ---------------------------------------------------------------------------

_TYPO_FIXES = {
    "stautus": "status", "staus": "status", "satus": "status", "sttus": "status", "statu": "status",
    "memry": "memory", "memmory": "memory", "memroy": "memory", "memor": "memory",
    "ndoe": "node", "noed": "node", "ndoes": "nodes", "noeds": "nodes",
    "containr": "container", "contianer": "container", "contianers": "containers",
    "alerst": "alerts", "alterts": "alerts", "alers": "alerts",
    "fleeet": "fleet", "fleat": "fleet", "fllet": "fleet",
    "diks": "disk", "disck": "disk", "dsik": "disk",
    "netowrk": "network", "netwrok": "network", "newtork": "network", "netwok": "network",
    "maintenace": "maintenance", "maintenence": "maintenance", "mainteanance": "maintenance",
    "tempreature": "temperature", "temperture": "temperature", "tempetature": "temperature",
    "serever": "server", "sevrer": "server", "srver": "server",
    "clsuter": "cluster", "clutser": "cluster",
    "uptme": "uptime", "uptiem": "uptime",
}

_TYPO_PATTERN = re.compile(
    r"\b(" + "|".join(re.escape(k) for k in _TYPO_FIXES) + r")\b",
    re.IGNORECASE,
)


def _normalize_typos(text: str) -> str:
    """Replace known typos in core NLQ keywords with canonical forms."""
    return _TYPO_PATTERN.sub(lambda m: _TYPO_FIXES[m.group(1).lower()], text)


# ---------------------------------------------------------------------------
# Multilingual input normalization
# ---------------------------------------------------------------------------
#
# Maps domain keywords in German, French, Spanish and Ukrainian to their
# English canonical tokens so the existing English handler patterns match
# queries asked in any of the 5 UI languages.
#
# Phase 1 (this): INPUT only. User can ask "wie ist der zustand vom fleet?"
# or "estado de pve-storage" and it routes to the right handler. Response
# text is still English.
#
# Phase 2 (later): localize handler response templates.
#
# Rules of thumb for what to include:
#   - Domain-relevant content words (status, memory, disk, network, …)
#   - Greetings ("hola", "salut", "hallo", …) so the greeting handler fires
#   - A few connectors ("wie", "comment", "cómo", "як") so how-questions match
# And what to EXCLUDE:
#   - Short function words (de, la, el, ist, sind, est, sont) — too ambiguous
#     with English tokens and the handlers already tolerate extra noise
#   - Words whose English spelling collides with something meaningful
#     (e.g. Spanish "red" = network, but "red" is also an English color word —
#     we skip it and rely on "trafico"/"traffic" instead)

_LANG_KEYWORDS: dict[str, str] = {
    # --- German ---
    "zustand": "status",
    "gesundheit": "health",
    "speicher": "memory",
    "arbeitsspeicher": "memory",
    "festplatte": "disk",
    "speicherplatz": "disk",
    "temperatur": "temperature",
    "knoten": "node",
    "rechner": "machine",
    "warnung": "alert",
    "warnungen": "alerts",
    "fehler": "error",
    "netzwerk": "network",
    "flotte": "fleet",
    "flottenstatus": "fleet status",
    "auslastung": "usage",
    "verkehr": "traffic",
    "bandbreite": "bandwidth",
    "wartung": "maintenance",
    "wie": "how",
    "läuft": "is",  # "wie läuft X" → "how is X" (colloquial German for status)
    "behälter": "container",
    "hallo": "hi",
    "hey": "hi",  # shared — passthrough
    # German action verbs (for howto / inventory / out-of-scope handlers):
    "hinzufügen": "add",
    "hinzu": "",           # separable prefix — discarded so "füge X hinzu" → "add X"
    "füge": "add",
    "installiere": "install",
    "installieren": "install",
    "registriere": "register",
    "registrieren": "register",
    "verbinde": "connect",
    "verbinden": "connect",
    "einrichten": "setup",
    "aktualisiere": "update",
    "aktualisieren": "update",
    "aktualisierung": "update",
    "lösche": "delete",
    "löschen": "delete",
    "entferne": "remove",
    "entfernen": "remove",
    "stummschalten": "silence",
    "stummschaltung": "silence",
    "auflisten": "list",
    "auflistung": "list",
    "zeige": "show",
    "zeigen": "show",
    "liste": "list",
    "erzähl": "tell",
    "erzähle": "tell",
    "witz": "joke",
    "wetter": "weather",
    "vorhersage": "forecast",
    "prognose": "forecast",
    "wachstum": "growth",
    "trend": "trend",
    # connectors / copulas (no English collision):
    "auf": "on",
    "vom": "of",
    "von": "of",
    "ist": "is",
    "sind": "are",
    "einen": "a",
    "eine": "a",
    "einer": "a",
    "einem": "a",
    "ich": "i",
    "mir": "me",
    "mich": "me",
    "meiner": "my",
    "meinem": "my",
    "meinen": "my",
    "geht": "is",   # "wie geht's" / "wie geht es X" = "how is X"
    "geht es": "is",  # compound — "wie geht es der flotte" → "how is fleet"
    # German articles — drop so "how is der fleet" → "how is fleet"
    "der": "",
    "die": "",
    "das": "",
    "den": "",
    "dem": "",
    "des": "",
    # --- French ---
    "statut": "status",
    "état": "status",
    "santé": "health",
    "mémoire": "memory",
    "disque": "disk",
    "stockage": "storage",
    "température": "temperature",
    "nœud": "node",
    "nœuds": "nodes",
    "noeud": "node",
    "noeuds": "nodes",
    "serveur": "server",
    "conteneur": "container",
    "conteneurs": "containers",
    "alerte": "alert",
    "alertes": "alerts",
    "erreur": "error",
    "réseau": "network",
    "utilisation": "usage",
    "trafic": "traffic",
    "comment": "how",
    "quelle": "what",
    "quel": "what",
    "quelle est": "what is",
    "quel est": "what is",
    "salut": "hi",
    "bonjour": "hi",
    # French action verbs:
    "ajouter": "add",
    "ajoute": "add",
    "installer": "install",
    "installe": "install",
    "enregistrer": "register",
    "connecter": "connect",
    "configurer": "configure",
    "supprimer": "delete",
    "supprime": "delete",
    "retirer": "remove",
    "mettre": "update",    # "mettre à jour" = update (à and jour also drop in noise)
    "mettez": "update",
    "mise": "update",
    "lister": "list",
    "liste": "list",
    "listez": "list",
    "montre": "show",
    "montrer": "show",
    "afficher": "show",
    "raconte-moi": "tell me",
    "raconte": "tell",
    "raconter": "tell",
    "moi": "me",
    "blague": "joke",
    "météo": "weather",
    "prévision": "forecast",
    "prédiction": "forecast",
    "tendance": "trend",
    "silencer": "silence",
    # connectors / copulas (no English collision):
    "sur": "on",
    "pour": "for",
    "va": "is",    # "comment va X" = how is X
    "vont": "are",
    "un": "a",
    "une": "a",
    "mon": "my",
    "ma": "my",
    "mes": "my",
    # French articles — drop so "how is la fleet" → "how is fleet"
    "la": "",
    "le": "",
    "les": "",
    # --- Spanish ---
    "estado": "status",
    "salud": "health",
    "memoria": "memory",
    "disco": "disk",
    "almacenamiento": "storage",
    "temperatura": "temperature",
    "nodo": "node",
    "nodos": "nodes",
    "servidor": "server",
    "máquina": "machine",
    "contenedor": "container",
    "contenedores": "containers",
    "alerta": "alert",
    "alertas": "alerts",
    "problema": "problem",
    "flota": "fleet",
    "uso": "usage",
    "tráfico": "traffic",
    "mantenimiento": "maintenance",
    "cómo": "how",
    "hola": "hi",
    # Spanish action verbs:
    "añadir": "add",
    "añade": "add",
    "agregar": "add",
    "agrega": "add",
    "instalar": "install",
    "instala": "install",
    "registrar": "register",
    "conectar": "connect",
    "configurar": "configure",
    "eliminar": "delete",
    "elimina": "delete",
    "borrar": "delete",
    "quitar": "remove",
    "actualizar": "update",
    "actualiza": "update",
    "listar": "list",
    "lista": "list",
    "mostrar": "show",
    "muestra": "show",
    "cuenta": "tell",
    "cuéntame": "tell me",
    "cuentame": "tell me",
    "chiste": "joke",
    "clima": "weather",
    "tiempo": "weather",   # colloquial — also "time" but rarely used in monitoring
    "predicción": "forecast",
    "pronóstico": "forecast",
    "tendencia": "trend",
    "silenciar": "silence",
    # connectors / copulas (no English collision):
    "para": "for",
    "sobre": "about",
    "en": "on",      # Spanish "en" = in/on; rare enough in English queries
    "está": "is",
    "están": "are",
    "un": "a",
    "una": "a",
    "mi": "my",
    "mis": "my",
    # Spanish articles — drop so "cómo está la flota" → "how is fleet"
    # (la/le/les already mapped above; reuse covers es + fr + it)
    "el": "",
    "los": "",
    "las": "",
    # --- Ukrainian ---
    "статус": "status",
    "стан": "status",
    "пам'ять": "memory",
    "памʼять": "memory",
    "пам’ять": "memory",
    "диск": "disk",
    "температура": "temperature",
    "вузол": "node",
    "вузли": "nodes",
    "вузлів": "nodes",
    "сервер": "server",
    "контейнер": "container",
    "контейнери": "containers",
    "попередження": "alert",
    "тривога": "alert",
    "помилка": "error",
    "проблема": "problem",
    "мережа": "network",
    "флот": "fleet",
    "флоти": "fleet",
    "кластер": "cluster",
    # German question structure
    "welcher": "which",
    "welche": "which",
    "welches": "which",
    "meisten": "most",
    "verbraucht": "uses",
    "benutzt": "uses",
    "verwendet": "uses",
    "höchste": "highest",
    "niedrigste": "lowest",
    "wieviel": "how much",
    "am": "",  # German filler (am meisten = the most)
    # French question structure
    "serveurs": "servers",
    "quels": "which",
    "utilisent": "uses",
    "utilise": "uses",
    "combien": "how much",
    # Spanish question structure
    "cuáles": "which",
    "servidores": "servers",
    "utilizan": "uses",
    "cuánto": "how much",
    "más": "most",
    # French additional
    "plus": "most",  # "le plus de" = "the most"
    "reste": "left",
    "disponible": "available",
    "de": "",  # French filler (du, de la)
    "espace": "space",
    # German additional structure
    "zeig": "show",      # informal imperative (zeig mir = show me)
    "alle": "all",       # all (zeig mir alle server = show me all servers)
    "alles": "everything",
    "gibt": "is",        # "gibt es" = "is there" / "are there"
    "es": "there",       # part of "gibt es"
    "aufmerksamkeit": "attention",
    "was": "what",
    "welchen": "which",
    "braucht": "needs",  # "braucht" = needs; for "am meisten" context, pattern still matches
    # French additional structure
    "montrez-moi": "show me",  # formal imperative + me
    "montrez": "show",   # formal/plural imperative
    "affichez": "show",  # formal/plural imperative
    "tous": "all",       # all (masculine)
    "toutes": "all",     # all (feminine)
    "quelles": "which",  # feminine plural
    "lesquels": "which",
    "lesquelles": "which",
    # Spanish additional structure
    "qué": "what",
    "muéstrame": "show me",
    "caídos": "down",    # "están caídos" = "are down"
    "caído": "down",
    "todos": "all",
    "todas": "all",
    "використання": "usage",
    "трафік": "traffic",
    "обслуговування": "maintenance",
    "як": "how",
    "що": "what",
    "привіт": "hi",
    "всі": "all",
    # Ukrainian action verbs:
    "додати": "add",
    "додай": "add",
    "встановити": "install",
    "встанови": "install",
    "зареєструвати": "register",
    "підключити": "connect",
    "налаштувати": "configure",
    "видалити": "delete",
    "видали": "delete",
    "прибрати": "remove",
    "оновити": "update",
    "онови": "update",
    "перелічити": "list",
    "показати": "show",
    "покажи": "show",
    "розповідж": "tell",
    "розкажи": "tell",
    "жарт": "joke",
    "погода": "weather",
    "прогноз": "forecast",
    "зростання": "growth",
    "працює": "is",        # works/runs → "як працює X" = "how is X"
    "працюють": "are",      # plural: works/run
    "є": "any",             # is there / are there → matches attention pattern
    "проблеми": "problems",
    "помилки": "errors",
    "заглушити": "silence",
    # connectors (Cyrillic, no English collision):
    "на": "on",
    "для": "for",
    "мій": "my",
    "моя": "my",
    "мої": "my",
}

_LANG_PATTERN = re.compile(
    # Sort by descending length so multi-word / compound mappings
    # ("raconte-moi" → "tell me") match before their prefixes ("raconte").
    r"(?<!\w)("
    + "|".join(
        re.escape(k)
        for k in sorted(_LANG_KEYWORDS.keys(), key=len, reverse=True)
    )
    + r")(?!\w)",
    re.IGNORECASE | re.UNICODE,
)


def _normalize_language(text: str) -> str:
    """Translate foreign-language domain keywords to English canonical tokens.

    Runs after typo normalization so misspellings in the user's native
    language are caught first (none configured yet) and before handler
    matching so the English regex handlers see English tokens.

    Articles and separable prefixes map to the empty string; we collapse
    the resulting double spaces so downstream handler regexes (which use
    literal single spaces) still match cleanly.
    """
    substituted = _LANG_PATTERN.sub(lambda m: _LANG_KEYWORDS[m.group(1).lower()], text)
    return re.sub(r"\s+", " ", substituted).strip()


def _scoped_list_labs() -> list[dict]:
    """Return labs visible within the current scope (user-filtered or all)."""
    email = _scope_email.get()
    if email is not None:
        return db.get_labs_for_email(email)
    return db.list_labs()


def _scoped_lab_ids() -> set[str] | None:
    """Return set of lab IDs visible to current user, or None for admin (all)."""
    email = _scope_email.get()
    if email is not None:
        return {lab["id"] for lab in db.get_labs_for_email(email)}
    return None


def _scoped_all_active_alerts() -> list[dict]:
    """get_all_active_alerts() filtered to user-visible labs."""
    alerts = db.get_all_active_alerts()
    allowed = _scoped_lab_ids()
    if allowed is None:
        return alerts
    return [a for a in alerts if a.get("lab_id") in allowed]


def _scoped_alerts_in_range(**kwargs) -> list[dict]:
    """get_alerts_in_range() filtered to user-visible labs."""
    alerts = db.get_alerts_in_range(**kwargs)
    allowed = _scoped_lab_ids()
    if allowed is None:
        return alerts
    return [a for a in alerts if a.get("lab_id") in allowed]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _lab_is_online(last_seen: Optional[str], threshold_minutes: int = 5) -> bool:
    """Check if a lab has reported within the threshold."""
    if not last_seen:
        return False
    try:
        ts = datetime.fromisoformat(last_seen)
        return (datetime.now(timezone.utc) - ts) < timedelta(minutes=threshold_minutes)
    except (ValueError, TypeError):
        return False


def _find_lab(name: str) -> Optional[dict]:
    """Find a lab by fuzzy hostname match. Empty input returns None."""
    labs = _scoped_list_labs()
    name_lower = name.lower().strip()
    if not name_lower:
        return None

    # Exact match
    for lab in labs:
        if lab["hostname"].lower() == name_lower:
            return lab

    # Partial match — input is substring of hostname or vice versa
    for lab in labs:
        hostname_lower = lab["hostname"].lower()
        if name_lower in hostname_lower or hostname_lower in name_lower:
            return lab

    # Word-boundary match — any word in the hostname matches
    for lab in labs:
        hostname_words = re.split(r"[-_.\s]+", lab["hostname"].lower())
        if name_lower in hostname_words:
            return lab

    return None


def _extract_node_name(text: str) -> Optional[str]:
    """Try to extract a hostname/node name from query text."""
    labs = _scoped_list_labs()
    text_lower = text.lower()

    # Check each known hostname against the text
    for lab in labs:
        hostname = lab["hostname"].lower()
        if hostname in text_lower:
            return lab["hostname"]
        # Also check short forms (e.g., "pve" matching "pve-storage")
        for word in re.split(r"[-_.\s]+", hostname):
            if len(word) >= 3 and re.search(r'\b' + re.escape(word) + r'\b', text_lower):
                # Only return if unambiguous (one match)
                matches = [l for l in labs if word in l["hostname"].lower()]
                if len(matches) == 1:
                    return matches[0]["hostname"]

    return None


def _parse_time_range(text: str) -> tuple[datetime, datetime]:
    """Parse time references from natural language."""
    now = datetime.now(timezone.utc)

    # "last night" / "overnight"
    if "last night" in text or "overnight" in text:
        if now.hour >= 6:
            start = now.replace(hour=22, minute=0, second=0, microsecond=0) - timedelta(days=1)
            end = now.replace(hour=6, minute=0, second=0, microsecond=0)
        else:
            start = (now - timedelta(days=1)).replace(hour=22, minute=0, second=0, microsecond=0)
            end = now
        return start, end

    # "last X hours" (cap at 1 year)
    hours_match = re.search(r'last\s+(\d+)\s+hours?', text)
    if hours_match:
        hours = min(int(hours_match.group(1)), 8760)
        return now - timedelta(hours=hours), now

    # "last X minutes" (cap at 1 year)
    mins_match = re.search(r'last\s+(\d+)\s+min(?:utes?)?', text)
    if mins_match:
        mins = min(int(mins_match.group(1)), 525600)
        return now - timedelta(minutes=mins), now

    # "last X days" (cap at 1 year)
    days_match = re.search(r'last\s+(\d+)\s+days?', text)
    if days_match:
        days = min(int(days_match.group(1)), 365)
        return now - timedelta(days=days), now

    # "this week"
    if "this week" in text:
        start = now - timedelta(days=now.weekday())
        return start.replace(hour=0, minute=0, second=0, microsecond=0), now

    # "yesterday"
    if "yesterday" in text:
        yesterday = now - timedelta(days=1)
        return (
            yesterday.replace(hour=0, minute=0, second=0, microsecond=0),
            yesterday.replace(hour=23, minute=59, second=59, microsecond=0),
        )

    # "today"
    if "today" in text:
        return now.replace(hour=0, minute=0, second=0, microsecond=0), now

    # Default: last 24 hours
    return now - timedelta(hours=24), now


def _extract_system_summary(metrics: dict[str, Any]) -> dict[str, Any]:
    """Pull top-level numbers from the latest system metrics."""
    system_entry = metrics.get("system", {})
    data = system_entry.get("data", {}) if isinstance(system_entry, dict) else {}
    cpu = data.get("cpu", {})
    mem = data.get("memory", {})
    disks = data.get("disk", data.get("disks", []))
    disk_pct = disks[0].get("used_percent", 0) if isinstance(disks, list) and disks else 0
    load_avg = data.get("load_average", {})

    load_1m = 0
    if isinstance(load_avg, dict):
        load_1m = load_avg.get("load1", 0) or 0
    elif isinstance(load_avg, (list, tuple)) and load_avg:
        load_1m = load_avg[0] or 0

    return {
        "cpu_percent": cpu.get("total_percent", 0) or 0,
        "memory_percent": mem.get("used_percent", 0) or 0,
        "disk_percent": disk_pct or 0,
        "uptime_seconds": data.get("uptime_seconds", 0) or 0,
        "load_1m": load_1m,
        "cpu_count": cpu.get("count", 0) or 0,
        "memory_total_bytes": mem.get("total_bytes", 0),
        "disks": disks if isinstance(disks, list) else [],
        "temperatures": data.get("temperatures", []),
        "processes": data.get("processes", []),
    }


def _extract_gpu_summary(metrics: dict[str, Any]) -> dict[str, Any]:
    """Pull GPU metrics from latest gpu collector data."""
    gpu_entry = metrics.get("gpu", {})
    data = gpu_entry.get("data", {}) if isinstance(gpu_entry, dict) else {}
    devices = data.get("devices", [])
    return {
        "gpu_count": data.get("count", len(devices) if isinstance(devices, list) else 0),
        "gpus": devices if isinstance(devices, list) else [],
    }


def _extract_docker_summary(metrics: dict[str, Any]) -> dict[str, Any]:
    """Pull container summary from latest docker metrics."""
    docker_entry = metrics.get("docker", {})
    data = docker_entry.get("data", {}) if isinstance(docker_entry, dict) else {}
    containers = data.get("containers", [])
    running = sum(1 for c in containers if c.get("state") == "running") if isinstance(containers, list) else 0
    return {
        "container_count": len(containers) if isinstance(containers, list) else 0,
        "containers_running": running,
        "containers": containers if isinstance(containers, list) else [],
    }


def _format_uptime(seconds: int) -> str:
    """Human-readable uptime."""
    if seconds <= 0:
        return "unknown"
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    if days > 0:
        return f"{days}d {hours}h"
    if hours > 0:
        mins = (seconds % 3600) // 60
        return f"{hours}h {mins}m"
    mins = seconds // 60
    return f"{mins}m"


def _metric_color(value: float) -> str:
    """Semantic assessment of a metric percentage."""
    if value >= 90:
        return "critical"
    if value >= 80:
        return "high"
    if value >= 60:
        return "moderate"
    return "healthy"


def _build_response(
    answer: str,
    query_type: str,
    confidence: float,
    sources: Optional[list] = None,
) -> dict:
    """Build the standard response dict."""
    return {
        "answer": answer,
        "query_type": query_type,
        "confidence": confidence,
        "sources": sources or [],
    }


# ---------------------------------------------------------------------------
# Handler: Status queries
# ---------------------------------------------------------------------------

_STATUS_PATTERN = re.compile(
    r"(?:is|how(?:'s| is)|status (?:of|for)|check|what(?:'s| is) (?:the )?(?:status|state) (?:of|for)"
    r"|tell\s+me\s+about|info\s+(?:on|about)|details?\s+(?:on|about))\s+"
    r"(.+?)(?:\s+(?:doing|running|ok(?:ay)?|up|online|healthy|down))?$"
)

_STATUS_SIMPLE_PATTERN = re.compile(
    r"^(.+?)(?:\s+(?:status|state|health|ok|okay|up|down|running|online|offline))\s*$"
)


def _handle_status(question: str, match: re.Match) -> dict:
    """Handle: 'Is plex running?', 'Status of pve-storage', 'How's pve?'"""
    # Extract the node/service name from the match
    target_name = match.group(1).strip().rstrip("?. ")

    # Clean up common noise words
    for noise in ["the", "my", "our", "server", "node", "machine", "host"]:
        target_name = re.sub(r'\b' + noise + r'\b', '', target_name).strip()

    if not target_name:
        # Defensive: do NOT call _fallback_response (mutual recursion).
        return _build_response(
            answer=_t("status_no_target.response"),
            query_type="status_no_target",
            confidence=0.3,
            sources=[],
        )

    lab = _find_lab(target_name)
    if not lab:
        # Maybe it's a container name — search across all labs
        return _handle_container_status(target_name)

    # Found a lab — get its current state
    metrics = db.get_latest_metrics(lab["id"])
    system = _extract_system_summary(metrics)
    docker = _extract_docker_summary(metrics)
    gpu = _extract_gpu_summary(metrics)
    alerts = db.get_active_alerts(lab["id"])
    online = _lab_is_online(lab["last_seen"])

    status_word = _t("status.state_online") if online else _t("status.state_offline")
    cpu = system["cpu_percent"]
    mem = system["memory_percent"]
    disk = system["disk_percent"]
    uptime = _format_uptime(system["uptime_seconds"])

    parts = [_t("status.host_state", hostname=lab["hostname"], state=status_word)]

    if online:
        parts.append(_t("status.metric_line", cpu=cpu, mem=mem, disk=disk))
        if system["load_1m"] > 0:
            parts.append(_t("status.load_line", load=system["load_1m"]))
        if uptime != "unknown":
            parts.append(_t("status.uptime_line", uptime=uptime))
        if docker["container_count"] > 0:
            parts.append(
                _t(
                    "status.containers_line",
                    running=docker["containers_running"],
                    total=docker["container_count"],
                )
            )
        if gpu["gpu_count"] > 0:
            for g in gpu["gpus"]:
                g_name = g.get("name", "GPU")
                g_util = g.get("utilization_percent", 0)
                g_mem = g.get("memory", {})
                g_mem_pct = g_mem.get("used_percent", 0) if isinstance(g_mem, dict) else 0
                g_temp = g.get("temperature_celsius", 0)
                parts.append(
                    _t(
                        "status.gpu_line",
                        name=g_name,
                        util=g_util,
                        vram=g_mem_pct,
                        temp=g_temp,
                    )
                )
    else:
        if lab["last_seen"]:
            try:
                ts = datetime.fromisoformat(lab["last_seen"])
                ago = datetime.now(timezone.utc) - ts
                hours = ago.total_seconds() / 3600
                if hours < 1:
                    parts.append(
                        _t("status.last_seen_minutes", n=int(ago.total_seconds() / 60))
                    )
                elif hours < 24:
                    parts.append(_t("status.last_seen_hours", n=hours))
                else:
                    parts.append(_t("status.last_seen_days", n=hours / 24))
            except (ValueError, TypeError):
                parts.append(_t("status.last_seen_unknown"))

    if alerts:
        critical = sum(1 for a in alerts if a.get("severity") == "critical")
        warning = sum(1 for a in alerts if a.get("severity") == "warning")
        alert_parts = []
        if critical:
            alert_parts.append(_t("status.alert_critical", n=critical))
        if warning:
            alert_parts.append(_t("status.alert_warning", n=warning))
        plural = "s" if len(alerts) != 1 else ""
        parts.append(
            _t(
                "status.alerts_line",
                count=len(alerts),
                plural=plural,
                breakdown=", ".join(alert_parts),
            )
        )
        # Include the most recent alert message
        parts.append(_t("status.alerts_latest", message=alerts[0]["message"]))
    else:
        parts.append(_t("status.no_alerts"))

    return _build_response(
        answer=" ".join(parts),
        query_type="status",
        confidence=0.95,
        sources=[
            {"type": "lab", "hostname": lab["hostname"], "lab_id": lab["id"]},
            {"type": "metrics", "count": len(metrics)},
            {"type": "alerts", "count": len(alerts)},
        ],
    )


def _handle_container_status(container_name: str) -> dict:
    """Check if a container is running across all labs."""
    labs = _scoped_list_labs()
    name_lower = container_name.lower()

    for lab in labs:
        metrics = db.get_latest_metrics(lab["id"])
        docker = _extract_docker_summary(metrics)
        for container in docker["containers"]:
            cname = container.get("name", "").lower()
            if name_lower in cname or cname in name_lower:
                state = container.get("state", "unknown")
                status = container.get("status", "")
                restarts = container.get("restart_count", 0)

                parts = [f"Container '{container.get('name', container_name)}' on {lab['hostname']} is {state}."]
                if status:
                    parts.append(f"Status: {status}.")
                if restarts and restarts > 0:
                    parts.append(f"Restart count: {restarts}.")

                return _build_response(
                    answer=" ".join(parts),
                    query_type="status",
                    confidence=0.9,
                    sources=[
                        {"type": "lab", "hostname": lab["hostname"], "lab_id": lab["id"]},
                        {"type": "container", "name": container.get("name", container_name)},
                    ],
                )

    return _build_response(
        answer=_t("container_status.not_found", name=container_name),
        query_type="status",
        confidence=0.5,
        sources=[],
    )


# ---------------------------------------------------------------------------
# Handler: Overnight / time-range queries
# ---------------------------------------------------------------------------

_TIME_PATTERN = re.compile(
    r"(?:what (?:happened|occurred|went (?:on|wrong))|show me|tell me about|anything happen)"
    r".*?(?:last night|overnight|last \d+ (?:hours?|minutes?|mins?|days?)|yesterday|today|this week)"

    r"|(?:cpu|memory|mem|disk|load|ram)\s+(?:usage|use|utilization)\s+(?:over|for|in|during)\s+(?:the\s+)?(?:past|last|previous)\s+(?:hour|day|week|month|\d+\s*(?:h|d|hr|hours?|days?|weeks?|minutes?))"
)


def _handle_time(question: str, match: re.Match) -> dict:
    """Handle: 'What happened last night?', 'What happened in the last 6 hours?'"""
    start, end = _parse_time_range(question)

    # Check if a specific node was mentioned
    node_name = _extract_node_name(question)
    lab_filter = None
    if node_name:
        lab = _find_lab(node_name)
        if lab:
            lab_filter = lab

    start_iso = start.isoformat()
    end_iso = end.isoformat()

    # Determine human-readable period name
    diff_hours = (end - start).total_seconds() / 3600
    if "last night" in question or "overnight" in question:
        period_name = "overnight (22:00-06:00)"
    elif diff_hours <= 1:
        period_name = f"the last {int(diff_hours * 60)} minutes"
    elif diff_hours <= 48:
        period_name = f"the last {diff_hours:.0f} hours"
    else:
        period_name = f"the last {diff_hours / 24:.0f} days"

    # Fetch alerts in range (scoped to user's labs when applicable)
    if lab_filter:
        alerts = db.get_alerts_in_range(lab_id=lab_filter["id"], start=start_iso, end=end_iso)
    else:
        alerts = _scoped_alerts_in_range(start=start_iso, end=end_iso)

    fired = len(alerts)
    resolved = sum(1 for a in alerts if a.get("resolved_at"))
    active = fired - resolved

    parts = []
    scope = f"for {lab_filter['hostname']}" if lab_filter else "across the fleet"

    if fired == 0:
        parts.append(f"Quiet period {scope}. No alerts fired during {period_name}.")
    else:
        parts.append(f"In {period_name} {scope}: {fired} alert{'s' if fired != 1 else ''} fired ({resolved} resolved, {active} still active).")

        # Group alerts by type for summary
        by_type: dict[str, list] = {}
        for a in alerts:
            atype = a.get("alert_type", "unknown")
            by_type.setdefault(atype, []).append(a)

        type_summaries = []
        for atype, alert_list in by_type.items():
            label = atype.replace("_", " ")
            type_summaries.append(f"{len(alert_list)}x {label}")
        if type_summaries:
            parts.append(f"Breakdown: {', '.join(type_summaries)}.")

        # Show the most critical alerts
        critical = [a for a in alerts if a.get("severity") == "critical"]
        if critical:
            parts.append(f"Critical alerts: {', '.join(a['message'] for a in critical[:3])}")

    # Also check for any metric anomalies in the range for the filtered lab(s)
    if lab_filter:
        _add_metric_anomalies(parts, lab_filter, start, end)
    else:
        # Check all labs briefly
        labs = _scoped_list_labs()
        anomaly_nodes = []
        for lab in labs[:10]:  # cap at 10 to keep response fast
            metrics = db.get_latest_metrics(lab["id"])
            sys_summary = _extract_system_summary(metrics)
            issues = []
            if sys_summary["cpu_percent"] > 80:
                issues.append(f"CPU {sys_summary['cpu_percent']:.0f}%")
            if sys_summary["memory_percent"] > 85:
                issues.append(f"MEM {sys_summary['memory_percent']:.0f}%")
            if sys_summary["disk_percent"] > 85:
                issues.append(f"DISK {sys_summary['disk_percent']:.0f}%")
            if issues:
                anomaly_nodes.append(f"{lab['hostname']} ({', '.join(issues)})")
        if anomaly_nodes:
            parts.append(f"Current concerns: {'; '.join(anomaly_nodes)}.")

    return _build_response(
        answer=" ".join(parts),
        query_type="time_range",
        confidence=0.9,
        sources=[
            {"type": "alerts", "count": fired, "start": start_iso, "end": end_iso},
            {"type": "scope", "filter": lab_filter["hostname"] if lab_filter else "fleet"},
        ],
    )


def _add_metric_anomalies(parts: list, lab: dict, start: datetime, end: datetime) -> None:
    """Check for metric anomalies in the time range for a specific lab."""
    hours = max(1, int((end - start).total_seconds() / 3600))
    history = db.get_metrics_history(lab["id"], hours=hours)

    cpu_vals = []
    mem_vals = []
    for entry in history:
        if entry.get("metric_type") != "system":
            continue
        data = entry.get("data", {})
        cpu = data.get("cpu", {})
        mem = data.get("memory", {})
        if isinstance(cpu, dict) and cpu.get("total_percent") is not None:
            cpu_vals.append(cpu["total_percent"])
        if isinstance(mem, dict) and mem.get("used_percent") is not None:
            mem_vals.append(mem["used_percent"])

    if cpu_vals:
        cpu_max = max(cpu_vals)
        cpu_avg = sum(cpu_vals) / len(cpu_vals)
        if cpu_max > 80:
            parts.append(f"CPU peaked at {cpu_max:.1f}% (avg {cpu_avg:.1f}%).")
    if mem_vals:
        mem_max = max(mem_vals)
        mem_avg = sum(mem_vals) / len(mem_vals)
        if mem_max > 85:
            parts.append(f"Memory peaked at {mem_max:.1f}% (avg {mem_avg:.1f}%).")


# ---------------------------------------------------------------------------
# Handler: Comparative queries
# ---------------------------------------------------------------------------

_COMPARATIVE_PATTERN = re.compile(
    r"(?:which|what)\s+(?:servers?|nodes?|machines?|hosts?|labs?)\s+"
    r"(?:uses?|has|is using|consumes?|shows?)\s+(?:the\s+)?(?:most|highest|lowest|least|worst|best)\s+"
    r"(cpu|memory|mem|disk|load|ram|storage|gpu|vram)"
)

_COMPARATIVE_ALT_PATTERN = re.compile(
    r"(?:most|highest|lowest|least|worst|best)\s+(cpu|memory|mem|disk|load|ram|storage|gpu|vram)\s*(?:usage|use|consumption)?"
)

_COMPARATIVE_TOP_PATTERN = re.compile(
    r"(?:top|rank|compare|sort)\s+(?:by\s+)?(cpu|memory|mem|disk|load|ram|storage|gpu|vram)"

    r"|top\s+\d+\s+(cpu|memory|mem|disk|load|ram|storage|gpu|vram)\s*(?:consumers?|users?|hogs?)?"
)


def _handle_comparative(question: str, match: re.Match) -> dict:
    """Handle: 'Which server uses the most CPU?', 'What node has the highest load?'"""
    # group(1) may be None if matched by an alt pattern — extract metric from text
    g1 = match.group(1)
    if g1 is None:
        # Try to find a metric keyword in the matched text
        import re as _re
        m = _re.search(r'(cpu|memory|mem|disk|load|ram|storage|gpu|vram)', match.group(0))
        metric_raw = m.group(1) if m else 'cpu'
    else:
        metric_raw = g1.lower()
    is_gpu_metric = metric_raw in ("gpu", "vram")
    metric_map = {
        "cpu": "cpu_percent",
        "memory": "memory_percent",
        "mem": "memory_percent",
        "ram": "memory_percent",
        "disk": "disk_percent",
        "storage": "disk_percent",
        "load": "load_1m",
        "gpu": "gpu_utilization",
        "vram": "gpu_memory",
    }
    metric_key = metric_map.get(metric_raw, "cpu_percent")
    metric_label = {
        "cpu_percent": "CPU",
        "memory_percent": "Memory",
        "disk_percent": "Disk",
        "load_1m": "Load",
        "gpu_utilization": "GPU Utilization",
        "gpu_memory": "GPU VRAM",
    }.get(metric_key, metric_raw)

    # Determine sort direction
    ascending = any(w in question for w in ["lowest", "least", "best"])

    labs = _scoped_list_labs()
    lab_metrics = []
    for lab in labs:
        metrics = db.get_latest_metrics(lab["id"])
        online = _lab_is_online(lab["last_seen"])

        if is_gpu_metric:
            gpu = _extract_gpu_summary(metrics)
            if gpu["gpu_count"] == 0:
                continue  # Skip nodes without GPUs
            g = gpu["gpus"][0] if gpu["gpus"] else {}
            if metric_key == "gpu_utilization":
                value = g.get("utilization_percent", 0) or 0
            else:
                g_mem = g.get("memory", {})
                value = g_mem.get("used_percent", 0) if isinstance(g_mem, dict) else 0
        else:
            sys_summary = _extract_system_summary(metrics)
            value = sys_summary.get(metric_key, 0) or 0

        lab_metrics.append({
            "hostname": lab["hostname"],
            "value": value,
            "online": online,
            "lab_id": lab["id"],
        })

    lab_metrics.sort(key=lambda x: x["value"], reverse=not ascending)

    if not lab_metrics:
        return _build_response(
            answer="No labs registered yet, so nothing to compare.",
            query_type="comparative",
            confidence=0.9,
            sources=[],
        )

    direction = "lowest" if ascending else "highest"
    unit = "%" if metric_key != "load_1m" else ""

    lines = [f"{metric_label} usage ranking ({direction} first):"]
    for i, lm in enumerate(lab_metrics, 1):
        status = "" if lm["online"] else " [OFFLINE]"
        lines.append(f"  {i}. {lm['hostname']}: {lm['value']:.1f}{unit}{status}")

    # Add a quick assessment
    top = lab_metrics[0]
    if not ascending and top["value"] > 80:
        lines.append(f"\n{top['hostname']} is running hot — consider investigation.")
    elif ascending and top["value"] < 10:
        lines.append(f"\n{top['hostname']} is barely loaded — good candidate for additional workloads.")

    return _build_response(
        answer="\n".join(lines),
        query_type="comparative",
        confidence=0.95,
        sources=[{"type": "labs", "count": len(lab_metrics)}],
    )


# ---------------------------------------------------------------------------
# Handler: Diagnostic queries
# ---------------------------------------------------------------------------

_DIAGNOSTIC_PATTERN = re.compile(
    r"(?:why\s+is|what(?:'s| is)\s+(?:causing|wrong with|the (?:problem|issue) with)|diagnose|troubleshoot)\s+"
    r"(.+?)(?:\s+(?:slow|high|spiking|lagging|unresponsive|down|broken|failing))?"
    r"$"
)


def _handle_diagnostic(question: str, match: re.Match) -> dict:
    """Handle: 'Why is pve-storage slow?', 'What's causing high load?'"""
    target = match.group(1).strip().rstrip("?. ")

    # Clean noise
    for noise in ["the", "my", "our", "so", "really"]:
        target = re.sub(r'\b' + noise + r'\b', '', target).strip()

    # If target is a generic metric word, diagnose fleet-wide
    if target.lower() in ("load", "cpu", "memory", "disk", "lag", "everything"):
        return _handle_fleet_diagnostic(question, target.lower())

    lab = _find_lab(target)
    if not lab:
        return _build_response(
            answer=f"Could not find a node matching '{target}'. Registered nodes: {', '.join(l['hostname'] for l in _scoped_list_labs())}.",
            query_type="diagnostic",
            confidence=0.6,
            sources=[],
        )

    metrics = db.get_latest_metrics(lab["id"])
    sys_summary = _extract_system_summary(metrics)
    docker = _extract_docker_summary(metrics)
    gpu = _extract_gpu_summary(metrics)
    alerts = db.get_active_alerts(lab["id"])
    online = _lab_is_online(lab["last_seen"])

    if not online:
        return _build_response(
            answer=f"{lab['hostname']} is OFFLINE and not reporting metrics. Last contact was {lab['last_seen'] or 'unknown'}. Check if the agent is running and the host is reachable.",
            query_type="diagnostic",
            confidence=0.9,
            sources=[{"type": "lab", "hostname": lab["hostname"]}],
        )

    cpu = sys_summary["cpu_percent"]
    mem = sys_summary["memory_percent"]
    disk = sys_summary["disk_percent"]
    load = sys_summary["load_1m"]
    cpu_count = sys_summary["cpu_count"]

    findings: list[str] = []
    diagnosis_parts: list[str] = []

    # High load + low CPU = I/O pressure
    if load > (cpu_count * 2 if cpu_count else 4) and cpu < 30:
        findings.append("I/O pressure")
        diagnosis_parts.append(
            f"Load average ({load:.1f}) is high relative to CPU count ({cpu_count}) but CPU usage is low ({cpu:.0f}%). "
            "This pattern typically indicates disk or network I/O bottleneck — processes waiting on I/O rather than computing."
        )

    # High CPU
    if cpu > 80:
        findings.append("high CPU")
        diagnosis_parts.append(f"CPU at {cpu:.1f}% — significant compute pressure.")

    # High memory
    if mem > 85:
        findings.append("memory pressure")
        diagnosis_parts.append(f"Memory at {mem:.1f}% — risk of OOM conditions or heavy swap usage.")

    # High disk
    if disk > 85:
        findings.append("disk space")
        diagnosis_parts.append(f"Disk at {disk:.1f}% — approaching capacity. May cause slowdowns if filesystem is nearly full.")

    # GPU issues
    for g in gpu.get("gpus", []):
        g_name = g.get("name", "GPU")
        g_util = g.get("utilization_percent", 0) or 0
        g_mem = g.get("memory", {})
        g_mem_pct = g_mem.get("used_percent", 0) if isinstance(g_mem, dict) else 0
        g_temp = g.get("temperature_celsius", 0) or 0

        if g_util > 90:
            findings.append("GPU compute pressure")
            diagnosis_parts.append(f"{g_name} utilization at {g_util:.0f}% — GPU-bound workloads.")
        if g_mem_pct > 90:
            findings.append("GPU memory pressure")
            diagnosis_parts.append(f"{g_name} VRAM at {g_mem_pct:.0f}% — risk of CUDA OOM errors.")
        if g_temp > 85:
            findings.append("GPU overheating")
            diagnosis_parts.append(f"{g_name} at {g_temp:.0f}°C — thermal throttling likely. Check fans and airflow.")

    # Container issues
    restart_containers = [
        c for c in docker["containers"]
        if c.get("restart_count", 0) and c["restart_count"] > 3
    ]
    if restart_containers:
        names = [c.get("name", "?") for c in restart_containers]
        findings.append("container restarts")
        diagnosis_parts.append(f"Containers with excessive restarts: {', '.join(names)}.")

    # Active alerts
    if alerts:
        alert_msgs = [a["message"] for a in alerts[:3]]
        findings.append(f"{len(alerts)} active alert{'s' if len(alerts) != 1 else ''}")
        diagnosis_parts.append(f"Active alerts: {'; '.join(alert_msgs)}")

    if findings:
        summary = f"{lab['hostname']} shows {', '.join(findings)}."
        detail = " ".join(diagnosis_parts)
        answer = f"{summary} {detail}"
    else:
        answer = (
            f"{lab['hostname']} looks healthy. "
            f"CPU {cpu:.1f}%, Memory {mem:.1f}%, Disk {disk:.1f}%, Load {load:.2f}. "
            f"No anomalies detected — the issue may be application-level or transient."
        )

    return _build_response(
        answer=answer,
        query_type="diagnostic",
        confidence=0.85,
        sources=[
            {"type": "lab", "hostname": lab["hostname"], "lab_id": lab["id"]},
            {"type": "metrics", "findings": findings},
            {"type": "alerts", "count": len(alerts)},
        ],
    )


def _handle_fleet_diagnostic(question: str, focus: str) -> dict:
    """Diagnose a fleet-wide concern (e.g., 'Why is everything slow?')."""
    labs = _scoped_list_labs()
    issues = []

    for lab in labs:
        metrics = db.get_latest_metrics(lab["id"])
        sys_summary = _extract_system_summary(metrics)
        online = _lab_is_online(lab["last_seen"])

        if not online:
            issues.append(f"{lab['hostname']}: OFFLINE")
            continue

        node_issues = []
        if sys_summary["cpu_percent"] > 80:
            node_issues.append(f"CPU {sys_summary['cpu_percent']:.0f}%")
        if sys_summary["memory_percent"] > 85:
            node_issues.append(f"MEM {sys_summary['memory_percent']:.0f}%")
        if sys_summary["disk_percent"] > 85:
            node_issues.append(f"DISK {sys_summary['disk_percent']:.0f}%")
        if sys_summary["load_1m"] > (sys_summary["cpu_count"] * 2 if sys_summary["cpu_count"] else 4):
            node_issues.append(f"LOAD {sys_summary['load_1m']:.1f}")

        if node_issues:
            issues.append(f"{lab['hostname']}: {', '.join(node_issues)}")

    if not issues:
        answer = "All nodes look healthy. No resource pressure detected across the fleet. The issue may be network-related or application-specific."
    else:
        answer = f"Fleet diagnostic — {len(issues)} node{'s' if len(issues) != 1 else ''} with concerns:\n"
        answer += "\n".join(f"  - {i}" for i in issues)

    return _build_response(
        answer=answer,
        query_type="diagnostic",
        confidence=0.8,
        sources=[{"type": "fleet", "nodes_checked": len(labs)}],
    )


# ---------------------------------------------------------------------------
# Handler: Capacity queries
# ---------------------------------------------------------------------------

_CAPACITY_PATTERN = re.compile(
    r"(?:how much|am i|are we|is there)\s+.*?(?:disk|storage|space|capacity)"
    r"|(?:running out|low on|out of)\s+(?:disk|storage|space)"
    r"|disk\s+(?:usage|space|capacity|full)"
    r"|storage\s+(?:usage|status|full|capacity)"

    r"|how\s+much\s+(?:ram|memory|mem|disk|storage|space)\s+(?:(?:do\s+)?(?:i|we)\s+have\s+)?(?:is\s+)?(?:left|free|available|remaining)"
    r"|(?:any|are\s+there)\s+(?:disk|drive|hdd|ssd|nvme)\s+(?:failures?|errors?|problems?|issues?)"
    r"|^uptime$|^(?:show\s+)?uptime(?:\s+(?:for|of)\s+.+)?$"
    r"|^(?:free|available)\s+(?:space|disk|storage)$"
    r"|^(?:ram|memory|mem)$"
)



def _handle_memory_capacity(question: str) -> dict:
    """Sub-handler for memory/RAM capacity queries."""
    labs = _scoped_list_labs()
    nodes = []

    for lab in labs:
        metrics = db.get_latest_metrics(lab["id"])
        sys_summary = _extract_system_summary(metrics)
        online = _lab_is_online(lab["last_seen"])
        nodes.append({
            "hostname": lab["hostname"],
            "memory_percent": sys_summary["memory_percent"],
            "memory_total_gb": sys_summary.get("memory_total_bytes", 0) / (1024**3) if sys_summary.get("memory_total_bytes") else 0,
            "online": online,
        })

    nodes.sort(key=lambda x: x["memory_percent"], reverse=True)

    if not nodes:
        return _build_response(answer="No labs registered yet.", query_type="capacity", confidence=0.9, sources=[])

    lines = ["Memory usage across the fleet:"]
    for nd in nodes:
        status = "" if nd["online"] else " [OFFLINE]"
        bar = _metric_color(nd["memory_percent"])
        total = f" ({nd['memory_total_gb']:.1f} GB total)" if nd["memory_total_gb"] > 0 else ""
        free_pct = 100 - nd["memory_percent"]
        lines.append(f"  {nd['hostname']}: {nd['memory_percent']:.1f}% used, {free_pct:.1f}% free{total} ({bar}){status}")

    return _build_response(answer="\n".join(lines), query_type="capacity", confidence=0.95, sources=[{"type": "labs", "count": len(nodes)}])


def _handle_uptime_capacity(question: str) -> dict:
    """Sub-handler for uptime queries."""
    node_name = _extract_node_name(question)
    labs = _scoped_list_labs()
    if node_name:
        labs = [l for l in labs if l["hostname"].lower() == node_name.lower()]

    if not labs:
        return _build_response(answer="No matching nodes found.", query_type="capacity", confidence=0.5, sources=[])

    lines = ["Uptime:"]
    for lab in labs:
        metrics = db.get_latest_metrics(lab["id"])
        sys_summary = _extract_system_summary(metrics)
        uptime_s = sys_summary.get("uptime_seconds", 0)
        uptime_str = _format_uptime(int(uptime_s)) if uptime_s else "unknown"
        online = _lab_is_online(lab["last_seen"])
        status = "online" if online else "OFFLINE"
        lines.append(f"  {lab['hostname']}: {uptime_str} ({status})")

    return _build_response(answer="\n".join(lines), query_type="capacity", confidence=0.95, sources=[{"type": "labs", "count": len(labs)}])


def _handle_capacity(question: str, match: re.Match) -> dict:
    """Handle: 'How much disk space do I have?', 'Am I running out of storage?', 'How much RAM left?'"""
    # Detect if the query is about memory/RAM rather than disk
    is_memory_query = bool(re.search(r'\b(?:ram|memory|mem)\b', question))
    is_uptime_query = bool(re.search(r'\buptime\b', question))

    if is_uptime_query:
        return _handle_uptime_capacity(question)
    if is_memory_query:
        return _handle_memory_capacity(question)

    labs = _scoped_list_labs()
    node_disks = []

    for lab in labs:
        metrics = db.get_latest_metrics(lab["id"])
        sys_summary = _extract_system_summary(metrics)
        online = _lab_is_online(lab["last_seen"])
        disk_pct = sys_summary["disk_percent"]

        node_disks.append({
            "hostname": lab["hostname"],
            "disk_percent": disk_pct,
            "online": online,
            "disks": sys_summary["disks"],
        })

    node_disks.sort(key=lambda x: x["disk_percent"], reverse=True)

    if not node_disks:
        return _build_response(
            answer="No labs registered yet.",
            query_type="capacity",
            confidence=0.9,
            sources=[],
        )

    lines = ["Disk usage across the fleet:"]
    warnings = []

    for nd in node_disks:
        status = "" if nd["online"] else " [OFFLINE]"
        bar = _metric_color(nd["disk_percent"])
        lines.append(f"  {nd['hostname']}: {nd['disk_percent']:.1f}% ({bar}){status}")

        # List individual mount points if available
        for disk_entry in nd["disks"][:3]:
            if isinstance(disk_entry, dict):
                mount = disk_entry.get("mount_point", disk_entry.get("path", ""))
                used_pct = disk_entry.get("used_percent", 0)
                if mount and used_pct > 0:
                    total_gb = disk_entry.get("total_bytes", 0) / (1024**3) if disk_entry.get("total_bytes") else 0
                    free_gb = disk_entry.get("free_bytes", 0) / (1024**3) if disk_entry.get("free_bytes") else 0
                    if total_gb > 0:
                        lines.append(f"    {mount}: {used_pct:.1f}% ({free_gb:.1f} GB free of {total_gb:.1f} GB)")

        if nd["disk_percent"] > 90:
            warnings.append(f"{nd['hostname']} is CRITICAL at {nd['disk_percent']:.1f}% — needs immediate attention!")
        elif nd["disk_percent"] > 80:
            warnings.append(f"{nd['hostname']} approaching threshold at {nd['disk_percent']:.1f}%.")

    if warnings:
        lines.append("")
        lines.append("Warnings:")
        for w in warnings:
            lines.append(f"  {w}")
    else:
        lines.append("")
        lines.append("All nodes within safe disk thresholds.")

    return _build_response(
        answer="\n".join(lines),
        query_type="capacity",
        confidence=0.95,
        sources=[{"type": "labs", "count": len(node_disks)}],
    )


# ---------------------------------------------------------------------------
# Handler: Fleet overview
# ---------------------------------------------------------------------------

_FLEET_PATTERN = re.compile(
    r"(?:give me a |fleet |lab |overall )?"
    r"(?:summary|overview|status|health|report|rundown|sitrep)"
    r"|how(?:'s| is) (?:my |the |our )?(?:lab|fleet|cluster|everything|infra(?:structure)?)"
    r"|how(?:'s| is) everything"
    r"|what(?:'s| is) the (?:overall |current )?(?:state|status|health)"
    # Bare 'show me the fleet / my cluster / etc.' — no status keyword needed
    r"|(?:show|get|display)\s+(?:me\s+)?(?:the|my|our)?\s*(?:fleet|cluster|infra(?:structure)?|setup|environment|everything|all\s*(?:nodes|servers)?)"
    # 'memory usage' / 'cpu usage' / 'disk usage' with no target = fleet pulse
    r"|^(?:cpu|memory|disk|network|load)\s+(?:usage|use|utilization|util)$"
    r"|^(?:show\s+me\s+)?everything$"
    r"|(?:what.?s\s+going\s+on|how\s+are\s+things|what.?s\s+up)"
    r"|^all\s+(?:nodes|servers|labs|machines)$"
)


def _handle_fleet(question: str, match: re.Match) -> dict:
    """Handle: 'Give me a summary', 'How's everything?', 'Fleet status'"""
    # If a specific node name is mentioned, reroute to status handler
    node_name = _extract_node_name(question)
    if node_name:
        fake_match = re.match(r".*?(" + re.escape(node_name) + r")", question) or re.match(r"(.*)", question)
        return _handle_status(question, fake_match)

    labs = _scoped_list_labs()

    if not labs:
        return _build_response(
            answer=_t("fleet.no_labs"),
            query_type="fleet_overview",
            confidence=0.95,
            sources=[],
        )

    total = len(labs)
    online_count = 0
    offline_nodes = []
    total_alerts = 0
    critical_alerts = 0
    node_summaries = []

    for lab in labs:
        metrics = db.get_latest_metrics(lab["id"])
        sys_summary = _extract_system_summary(metrics)
        docker = _extract_docker_summary(metrics)
        alerts = db.get_active_alerts(lab["id"])
        online = _lab_is_online(lab["last_seen"])

        if online:
            online_count += 1
        else:
            offline_nodes.append(lab["hostname"])

        lab_critical = sum(1 for a in alerts if a.get("severity") == "critical")
        total_alerts += len(alerts)
        critical_alerts += lab_critical

        cpu = sys_summary["cpu_percent"]
        mem = sys_summary["memory_percent"]
        disk = sys_summary["disk_percent"]

        # GPU info
        gpu_info = _extract_gpu_summary(metrics)
        gpu_str = ""
        if gpu_info["gpu_count"] > 0 and gpu_info["gpus"]:
            g = gpu_info["gpus"][0]
            gpu_str = _t(
                "fleet.extra_gpu",
                util=g.get("utilization_percent", 0) or 0,
                temp=g.get("temperature_celsius", 0) or 0,
            )

        if online and not alerts:
            status_indicator = _t("fleet.node_status_ok")
        elif alerts:
            status_indicator = _t("fleet.node_status_alert")
        else:
            status_indicator = _t("fleet.node_status_offline")

        extras = gpu_str
        if docker["container_count"]:
            extras += _t("fleet.extra_containers", n=docker["container_count"])
        if alerts:
            extras += _t(
                "fleet.extra_alerts",
                n=len(alerts),
                plural="s" if len(alerts) != 1 else "",
            )

        node_summaries.append(
            _t(
                "fleet.node_line",
                hostname=lab["hostname"],
                status=status_indicator,
                cpu=cpu,
                mem=mem,
                disk=disk,
                extras=extras,
            )
        )

    # Build health summary
    if total_alerts == 0 and online_count == total:
        health = _t("fleet.health_healthy")
    elif critical_alerts > 0:
        health = _t(
            "fleet.health_critical",
            n=critical_alerts,
            plural="s" if critical_alerts != 1 else "",
        )
    elif offline_nodes:
        health = _t(
            "fleet.health_degraded",
            n=len(offline_nodes),
            plural="s" if len(offline_nodes) != 1 else "",
        )
    elif total_alerts > 0:
        health = _t(
            "fleet.health_mostly_healthy",
            n=total_alerts,
            plural="s" if total_alerts != 1 else "",
        )
    else:
        health = _t("fleet.health_normal")

    parts = [
        _t(
            "fleet.summary_line",
            total=total,
            total_plural="s" if total != 1 else "",
            online=online_count,
            alerts=total_alerts,
            alerts_plural="s" if total_alerts != 1 else "",
            health=health,
        )
    ]

    if offline_nodes:
        parts.append(_t("fleet.offline_line", nodes=", ".join(offline_nodes)))

    parts.append("")
    parts.append(_t("fleet.breakdown_header"))
    parts.extend(node_summaries)

    return _build_response(
        answer="\n".join(parts),
        query_type="fleet_overview",
        confidence=0.95,
        sources=[
            {"type": "fleet", "total": total, "online": online_count},
            {"type": "alerts", "total": total_alerts, "critical": critical_alerts},
        ],
    )


# ---------------------------------------------------------------------------
# Handler: Alert queries
# ---------------------------------------------------------------------------

_ALERT_PATTERN = re.compile(
    r"(?:show\s+(?:me\s+)?(?:all\s+)?|list\s+|what\s+|any\s+|get\s+)?"
    r"(?:active\s+|recent\s+|current\s+|open\s+|unresolved\s+)?"
    r"alerts?"
    r"|(?:any|are there(?: any)?)\s+alerts?"
)


def _handle_alerts(question: str, match: re.Match) -> dict:
    """Handle: 'Show me all alerts', 'Any alerts?', 'Recent alerts', 'Active alerts on pve'"""
    node_name = _extract_node_name(question)
    is_recent = "recent" in question

    if is_recent:
        # Show recent alerts including resolved ones (last 24h)
        now = datetime.now(timezone.utc)
        start = (now - timedelta(hours=24)).isoformat()
        end = now.isoformat()

        if node_name:
            lab = _find_lab(node_name)
            if lab:
                alerts = db.get_alerts_in_range(lab_id=lab["id"], start=start, end=end)
                scope = f"on {lab['hostname']}"
            else:
                alerts = _scoped_alerts_in_range(start=start, end=end)
                scope = "across the fleet"
        else:
            alerts = _scoped_alerts_in_range(start=start, end=end)
            scope = "across the fleet"

        if not alerts:
            return _build_response(
                answer=f"No alerts in the last 24 hours {scope}. All quiet.",
                query_type="alerts",
                confidence=0.95,
                sources=[{"type": "alerts", "count": 0, "period": "24h"}],
            )

        resolved = sum(1 for a in alerts if a.get("resolved_at"))
        active = len(alerts) - resolved
        critical = sum(1 for a in alerts if a.get("severity") == "critical")
        warning = sum(1 for a in alerts if a.get("severity") == "warning")
        info = sum(1 for a in alerts if a.get("severity") == "info")

        parts = [f"{len(alerts)} alert{'s' if len(alerts) != 1 else ''} in the last 24 hours {scope} ({active} active, {resolved} resolved)."]

        severity_parts = []
        if critical:
            severity_parts.append(f"{critical} critical")
        if warning:
            severity_parts.append(f"{warning} warning")
        if info:
            severity_parts.append(f"{info} info")
        if severity_parts:
            parts.append(f"Severity breakdown: {', '.join(severity_parts)}.")

        # Show most recent messages
        for a in alerts[:5]:
            hostname = a.get("hostname", "")
            host_prefix = f"[{hostname}] " if hostname else ""
            status = "ACTIVE" if not a.get("resolved_at") else "resolved"
            parts.append(f"  - {host_prefix}{a.get('severity', '?').upper()}: {a['message']} ({status})")

        return _build_response(
            answer="\n".join(parts),
            query_type="alerts",
            confidence=0.95,
            sources=[{"type": "alerts", "count": len(alerts), "period": "24h"}],
        )
    else:
        # Active alerts only
        if node_name:
            lab = _find_lab(node_name)
            if lab:
                alerts = db.get_active_alerts(lab["id"])
                scope = f"on {lab['hostname']}"
                sources = [
                    {"type": "lab", "hostname": lab["hostname"], "lab_id": lab["id"]},
                    {"type": "alerts", "count": len(alerts)},
                ]
            else:
                alerts = _scoped_all_active_alerts()
                scope = "across the fleet"
                sources = [{"type": "alerts", "count": len(alerts)}]
        else:
            alerts = _scoped_all_active_alerts()
            scope = "across the fleet"
            sources = [{"type": "alerts", "count": len(alerts)}]

        if not alerts:
            return _build_response(
                answer=f"No active alerts {scope}. Everything looks clean.",
                query_type="alerts",
                confidence=0.95,
                sources=sources,
            )

        critical = sum(1 for a in alerts if a.get("severity") == "critical")
        warning = sum(1 for a in alerts if a.get("severity") == "warning")
        info = sum(1 for a in alerts if a.get("severity") == "info")

        parts = [f"{len(alerts)} active alert{'s' if len(alerts) != 1 else ''} {scope}."]

        severity_parts = []
        if critical:
            severity_parts.append(f"{critical} critical")
        if warning:
            severity_parts.append(f"{warning} warning")
        if info:
            severity_parts.append(f"{info} info")
        if severity_parts:
            parts.append(f"Severity breakdown: {', '.join(severity_parts)}.")

        for a in alerts[:8]:
            hostname = a.get("hostname", "")
            host_prefix = f"[{hostname}] " if hostname else ""
            parts.append(f"  - {host_prefix}{a.get('severity', '?').upper()}: {a['message']}")

        if len(alerts) > 8:
            parts.append(f"  ... and {len(alerts) - 8} more.")

        return _build_response(
            answer="\n".join(parts),
            query_type="alerts",
            confidence=0.95,
            sources=sources,
        )


# ---------------------------------------------------------------------------
# Handler: Container queries
# ---------------------------------------------------------------------------

_CONTAINER_PATTERN = re.compile(
    r"(?:show|list|what|which|get|display)\s+.*?containers?"
    r"|containers?\s+(?:on|running|status|list|info)"
    r"|(?:which|what)\s+containers?\s+(?:uses?|has|is using|consumes?)\s+(?:the\s+)?(?:most|highest|lowest|least)\s+(?:cpu|memory|mem|ram)"
    r"|(?:most|highest)\s+(?:cpu|memory|mem|ram)\s+containers?"
    r"|running\s+containers?"
    r"|docker\s+(?:status|containers?|ps)"

    r"|(?:any|are\s+there)\s+(?:containers?|dockers?)\s+(?:crashed|failing|failed|down|stopped|dead|unhealthy)"
    r"|(?:crashed|failing|failed|down|stopped|dead|unhealthy)\s+containers?"
    r"|^(?:docker\s+)?containers?$"
)


def _handle_containers(question: str, match: re.Match) -> dict:
    """Handle: 'Show containers', 'Containers on pve-docker', 'Which container uses the most CPU?'"""
    node_name = _extract_node_name(question)

    # Detect comparative container queries
    comparative_match = re.search(
        r"(?:most|highest|lowest|least)\s+(cpu|memory|mem|ram)", question
    )
    is_comparative = comparative_match is not None

    labs = _scoped_list_labs()
    all_containers = []

    for lab in labs:
        if node_name:
            found = _find_lab(node_name)
            if found and lab["id"] != found["id"]:
                continue
        metrics = db.get_latest_metrics(lab["id"])
        docker = _extract_docker_summary(metrics)
        for c in docker["containers"]:
            c["_hostname"] = lab["hostname"]
            c["_lab_id"] = lab["id"]
            all_containers.append(c)

    if is_comparative and all_containers:
        metric_word = comparative_match.group(1).lower()
        ascending = any(w in question for w in ["lowest", "least"])

        if metric_word in ("memory", "mem", "ram"):
            sort_key = "memory_usage_bytes"
            label = "memory"
        else:
            sort_key = "cpu_percent"
            label = "CPU"

        # Filter containers that have the metric
        ranked = [c for c in all_containers if c.get(sort_key) is not None]
        if not ranked:
            # Fall back: try alternative keys
            if label == "memory":
                ranked = [c for c in all_containers if c.get("memory_usage") is not None]
                sort_key = "memory_usage"
            elif label == "CPU":
                ranked = [c for c in all_containers if c.get("cpu_usage") is not None]
                sort_key = "cpu_usage"

        if not ranked:
            return _build_response(
                answer=f"Container {label} metrics are not available. The agent may not be collecting per-container resource stats.",
                query_type="containers",
                confidence=0.7,
                sources=[],
            )

        ranked.sort(key=lambda c: c.get(sort_key, 0) or 0, reverse=not ascending)
        direction = "lowest" if ascending else "highest"

        lines = [f"Containers ranked by {label} usage ({direction} first):"]
        for i, c in enumerate(ranked[:10], 1):
            cname = c.get("name", "?")
            host = c.get("_hostname", "?")
            value = c.get(sort_key, 0) or 0
            if "bytes" in sort_key:
                value_str = f"{value / (1024**2):.1f} MB"
            elif "percent" in sort_key:
                value_str = f"{value:.1f}%"
            else:
                value_str = f"{value}"
            lines.append(f"  {i}. {cname} on {host}: {value_str}")

        return _build_response(
            answer="\n".join(lines),
            query_type="containers",
            confidence=0.9,
            sources=[{"type": "containers", "count": len(ranked)}],
        )

    # Non-comparative: list containers
    if not all_containers:
        scope = f"on {node_name}" if node_name else "across the fleet"
        return _build_response(
            answer=f"No containers found {scope}.",
            query_type="containers",
            confidence=0.9,
            sources=[],
        )

    running = [c for c in all_containers if c.get("state") == "running"]
    stopped = [c for c in all_containers if c.get("state") != "running"]
    scope = f"on {node_name}" if node_name else "across the fleet"

    parts = [f"{len(all_containers)} container{'s' if len(all_containers) != 1 else ''} {scope} ({len(running)} running, {len(stopped)} stopped)."]

    # Group by host
    by_host: dict[str, list] = {}
    for c in all_containers:
        host = c.get("_hostname", "unknown")
        by_host.setdefault(host, []).append(c)

    for host, containers in sorted(by_host.items()):
        host_running = sum(1 for c in containers if c.get("state") == "running")
        parts.append(f"\n{host} ({host_running}/{len(containers)} running):")
        for c in sorted(containers, key=lambda x: x.get("name", "")):
            cname = c.get("name", "?")
            state = c.get("state", "unknown")
            status = c.get("status", "")
            restarts = c.get("restart_count", 0)
            line = f"  - {cname}: {state}"
            if status:
                line += f" ({status})"
            if restarts and restarts > 0:
                line += f" [{restarts} restarts]"
            parts.append(line)

    return _build_response(
        answer="\n".join(parts),
        query_type="containers",
        confidence=0.95,
        sources=[{"type": "containers", "count": len(all_containers), "scope": scope}],
    )


# ---------------------------------------------------------------------------
# Handler: Temperature queries
# ---------------------------------------------------------------------------

_TEMPERATURE_PATTERN = re.compile(
    r"(?:how\s+hot|temperature|temps?|thermals?|overheating|heat)"
    r"|(?:is\s+.+?\s+overheating)"
    r"|(?:cpu|gpu|system)\s+temp(?:erature)?s?"
    r"|temp(?:erature)?s?\s+(?:on|of|for|across)"
)


def _handle_temperature(question: str, match: re.Match) -> dict:
    """Handle: 'How hot is pve-storage?', 'Show temps', 'Is pve overheating?'"""
    node_name = _extract_node_name(question)

    labs = _scoped_list_labs()
    node_temps = []

    for lab in labs:
        if node_name:
            found = _find_lab(node_name)
            if found and lab["id"] != found["id"]:
                continue

        metrics = db.get_latest_metrics(lab["id"])
        system = _extract_system_summary(metrics)
        gpu = _extract_gpu_summary(metrics)
        online = _lab_is_online(lab["last_seen"])

        temps = []

        # System/CPU temperatures
        for t in system.get("temperatures", []):
            if isinstance(t, dict):
                label = t.get("label", t.get("name", "CPU"))
                current = t.get("current", t.get("temperature_celsius", 0))
                if current and current > 0:
                    temps.append({"label": label, "value": current, "source": "system"})
            elif isinstance(t, (int, float)) and t > 0:
                temps.append({"label": "CPU", "value": t, "source": "system"})

        # GPU temperatures
        for g in gpu.get("gpus", []):
            g_name = g.get("name", "GPU")
            g_temp = g.get("temperature_celsius", 0)
            if g_temp and g_temp > 0:
                temps.append({"label": g_name, "value": g_temp, "source": "gpu"})

        max_temp = max((t["value"] for t in temps), default=0)
        node_temps.append({
            "hostname": lab["hostname"],
            "online": online,
            "temps": temps,
            "max_temp": max_temp,
        })

    # Sort hottest first
    node_temps.sort(key=lambda x: x["max_temp"], reverse=True)

    if node_name and len(node_temps) == 1:
        # Single node detail view
        nt = node_temps[0]
        if not nt["online"]:
            return _build_response(
                answer=f"{nt['hostname']} is OFFLINE. No current temperature data available.",
                query_type="temperature",
                confidence=0.9,
                sources=[{"type": "lab", "hostname": nt["hostname"]}],
            )

        if not nt["temps"]:
            return _build_response(
                answer=f"{nt['hostname']} is online but no temperature sensors are reporting. The agent may not have access to thermal data.",
                query_type="temperature",
                confidence=0.8,
                sources=[{"type": "lab", "hostname": nt["hostname"]}],
            )

        parts = [f"Temperatures on {nt['hostname']}:"]
        concerns = []
        for t in sorted(nt["temps"], key=lambda x: x["value"], reverse=True):
            assessment = ""
            if t["value"] >= 90:
                assessment = " -- CRITICAL"
                concerns.append(f"{t['label']} at {t['value']:.0f}C is critically hot")
            elif t["value"] >= 80:
                assessment = " -- concerning"
                concerns.append(f"{t['label']} at {t['value']:.0f}C is running hot")
            parts.append(f"  {t['label']}: {t['value']:.0f}C{assessment}")

        if concerns:
            parts.append("")
            parts.append("Thermal concerns: " + "; ".join(concerns) + ". Check cooling and airflow.")
        else:
            parts.append("")
            parts.append("All temperatures within normal range.")

        return _build_response(
            answer="\n".join(parts),
            query_type="temperature",
            confidence=0.95,
            sources=[{"type": "lab", "hostname": nt["hostname"]}],
        )

    # Fleet-wide temperature view
    if not node_temps:
        return _build_response(
            answer="No nodes registered.",
            query_type="temperature",
            confidence=0.9,
            sources=[],
        )

    has_any_temps = any(nt["temps"] for nt in node_temps)
    if not has_any_temps:
        return _build_response(
            answer="No temperature data available from any node. Agents may not have access to thermal sensors.",
            query_type="temperature",
            confidence=0.8,
            sources=[{"type": "fleet", "nodes_checked": len(node_temps)}],
        )

    parts = ["Temperature overview (sorted hottest first):"]
    concerns = []

    for nt in node_temps:
        if not nt["online"]:
            parts.append(f"  {nt['hostname']}: OFFLINE")
            continue
        if not nt["temps"]:
            parts.append(f"  {nt['hostname']}: no sensor data")
            continue

        temp_strs = []
        for t in sorted(nt["temps"], key=lambda x: x["value"], reverse=True):
            temp_strs.append(f"{t['label']} {t['value']:.0f}C")
            if t["value"] >= 90:
                concerns.append(f"{nt['hostname']} {t['label']} at {t['value']:.0f}C is CRITICAL")
            elif t["value"] >= 80:
                concerns.append(f"{nt['hostname']} {t['label']} at {t['value']:.0f}C is concerning")

        parts.append(f"  {nt['hostname']}: {', '.join(temp_strs)}")

    if concerns:
        parts.append("")
        parts.append("Thermal warnings:")
        for c in concerns:
            parts.append(f"  - {c}")
    else:
        parts.append("")
        parts.append("All nodes within normal thermal range.")

    return _build_response(
        answer="\n".join(parts),
        query_type="temperature",
        confidence=0.95,
        sources=[{"type": "fleet", "nodes_checked": len(node_temps)}],
    )


# ---------------------------------------------------------------------------
# Handler: Attention/Issues queries
# ---------------------------------------------------------------------------

_ATTENTION_PATTERN = re.compile(
    r"(?:any(?:thing)?\s+(?:wrong|broken|failing|down|concerning|off))"
    r"|(?:what\s+needs?\s+(?:my\s+)?attention)"
    r"|(?:show\s+(?:me\s+)?(?:problems?|issues?))"
    r"|(?:any\s+(?:problems?|issues?|concerns?))"
    r"|(?:what(?:'s| is)\s+(?:wrong|broken|failing))"
    r"|(?:problems?\s+(?:in|on|with|across)\s+)"
    r"|(?:needs?\s+attention)"
)


def _handle_attention(question: str, match: re.Match) -> dict:
    """Handle: 'Any issues?', 'What needs attention?', 'Anything wrong?', 'Show me problems'"""
    labs = _scoped_list_labs()
    issues = []
    total_alerts = 0
    total_critical = 0

    for lab in labs:
        metrics = db.get_latest_metrics(lab["id"])
        system = _extract_system_summary(metrics)
        gpu = _extract_gpu_summary(metrics)
        alerts = db.get_active_alerts(lab["id"])
        online = _lab_is_online(lab["last_seen"])

        node_issues = []

        # Offline node is an issue
        if not online:
            node_issues.append({
                "severity": "critical",
                "detail": "Node is OFFLINE",
            })

        # Active alerts
        for a in alerts:
            total_alerts += 1
            sev = a.get("severity", "warning")
            if sev == "critical":
                total_critical += 1
            node_issues.append({
                "severity": sev,
                "detail": f"Alert: {a['message']}",
            })

        # Resource pressure (only if online and we have data)
        if online:
            cpu = system["cpu_percent"]
            mem = system["memory_percent"]
            disk = system["disk_percent"]
            load = system["load_1m"]
            cpu_count = system["cpu_count"]

            if cpu > 90:
                node_issues.append({"severity": "critical", "detail": f"CPU at {cpu:.1f}%"})
            elif cpu > 80:
                node_issues.append({"severity": "warning", "detail": f"CPU at {cpu:.1f}%"})

            if mem > 90:
                node_issues.append({"severity": "critical", "detail": f"Memory at {mem:.1f}%"})
            elif mem > 85:
                node_issues.append({"severity": "warning", "detail": f"Memory at {mem:.1f}%"})

            if disk > 90:
                node_issues.append({"severity": "critical", "detail": f"Disk at {disk:.1f}%"})
            elif disk > 85:
                node_issues.append({"severity": "warning", "detail": f"Disk at {disk:.1f}%"})

            if load > (cpu_count * 2 if cpu_count else 4):
                node_issues.append({"severity": "warning", "detail": f"High load average: {load:.2f} (vs {cpu_count} cores)"})

            # GPU temps
            for g in gpu.get("gpus", []):
                g_temp = g.get("temperature_celsius", 0) or 0
                g_name = g.get("name", "GPU")
                if g_temp >= 90:
                    node_issues.append({"severity": "critical", "detail": f"{g_name} at {g_temp:.0f}C — overheating"})
                elif g_temp >= 80:
                    node_issues.append({"severity": "warning", "detail": f"{g_name} at {g_temp:.0f}C — running hot"})

        if node_issues:
            # Sort by severity (critical first)
            severity_order = {"critical": 0, "warning": 1, "info": 2}
            node_issues.sort(key=lambda x: severity_order.get(x["severity"], 3))
            issues.append({
                "hostname": lab["hostname"],
                "issues": node_issues,
                "worst_severity": node_issues[0]["severity"],
            })

    if not issues:
        return _build_response(
            answer=f"All clear. {len(labs)} node{'s' if len(labs) != 1 else ''} checked — no active alerts, no resource pressure, everything is running normally.",
            query_type="attention",
            confidence=0.95,
            sources=[{"type": "fleet", "nodes_checked": len(labs), "issues": 0}],
        )

    # Sort nodes by worst severity
    severity_order = {"critical": 0, "warning": 1, "info": 2}
    issues.sort(key=lambda x: severity_order.get(x["worst_severity"], 3))

    total_issues = sum(len(n["issues"]) for n in issues)
    critical_nodes = sum(1 for n in issues if n["worst_severity"] == "critical")

    if critical_nodes:
        header = f"{total_issues} issue{'s' if total_issues != 1 else ''} found across {len(issues)} node{'s' if len(issues) != 1 else ''} — {critical_nodes} need{'s' if critical_nodes == 1 else ''} immediate attention."
    else:
        header = f"{total_issues} issue{'s' if total_issues != 1 else ''} found across {len(issues)} node{'s' if len(issues) != 1 else ''}, none critical."

    parts = [header]

    for node in issues:
        severity_icon = "CRITICAL" if node["worst_severity"] == "critical" else "WARNING"
        parts.append(f"\n{node['hostname']} [{severity_icon}]:")
        for issue in node["issues"]:
            sev = issue["severity"].upper()
            parts.append(f"  - [{sev}] {issue['detail']}")

    return _build_response(
        answer="\n".join(parts),
        query_type="attention",
        confidence=0.95,
        sources=[
            {"type": "fleet", "nodes_checked": len(labs), "nodes_with_issues": len(issues)},
            {"type": "alerts", "total": total_alerts, "critical": total_critical},
        ],
    )


# ---------------------------------------------------------------------------
# Handler: Network queries
# ---------------------------------------------------------------------------

_NETWORK_PATTERN = re.compile(
    r"(?:network|bandwidth|traffic|throughput|mbps|rx|tx)"
    r"|(?:how much|what(?:'s| is))\s+(?:the\s+)?(?:network|bandwidth|traffic)"
    r"|(?:data|bytes)\s+(?:transfer|usage|rate)"
    r"|(?:upload|download)\s+(?:speed|rate|bandwidth)"
    r"|(?:net(?:work)?\s+(?:usage|speed|rate|stats|status))"
)


def _handle_network(question: str, match: re.Match) -> dict:
    """Handle: 'network usage', 'bandwidth', 'what's the traffic?'"""
    labs = _scoped_list_labs()

    if not labs:
        return _build_response(
            answer="No nodes registered yet.",
            query_type="network",
            confidence=0.9,
            sources=[],
        )

    # Check if asking about a specific node
    specific_lab = None
    for lab in labs:
        if lab["hostname"].lower() in question.lower():
            specific_lab = lab
            break

    if specific_lab:
        return _network_for_lab(specific_lab)

    # All labs
    parts = ["Network usage across all nodes:"]
    any_data = False
    for lab in labs:
        online = _lab_is_online(lab["last_seen"])
        if not online:
            parts.append(f"  - {lab['hostname']}: OFFLINE")
            continue

        rates = _get_network_rates(lab["id"])
        if rates:
            any_data = True
            parts.append(
                f"  - {lab['hostname']}: {rates['rx']:.1f} Mbps rx / {rates['tx']:.1f} Mbps tx"
            )
        else:
            parts.append(f"  - {lab['hostname']}: no network data")

    if not any_data:
        return _build_response(
            answer="No network data available yet. The agent needs at least two metric samples to compute rates.",
            query_type="network",
            confidence=0.85,
            sources=[],
        )

    return _build_response(
        answer="\n".join(parts),
        query_type="network",
        confidence=0.9,
        sources=[{"type": "network", "node_count": len(labs)}],
    )


def _network_for_lab(lab: dict) -> dict:
    """Network details for a single lab."""
    online = _lab_is_online(lab["last_seen"])
    if not online:
        return _build_response(
            answer=f"{lab['hostname']} is currently offline.",
            query_type="network",
            confidence=0.9,
            sources=[{"type": "network", "node": lab["hostname"]}],
        )

    rates = _get_network_rates(lab["id"])
    if not rates:
        return _build_response(
            answer=f"No network rate data for {lab['hostname']} yet (needs at least two samples).",
            query_type="network",
            confidence=0.85,
            sources=[{"type": "network", "node": lab["hostname"]}],
        )

    return _build_response(
        answer=f"{lab['hostname']}: {rates['rx']:.1f} Mbps rx / {rates['tx']:.1f} Mbps tx",
        query_type="network",
        confidence=0.92,
        sources=[{"type": "network", "node": lab["hostname"], **rates}],
    )


def _get_network_rates(lab_id: str) -> Optional[dict]:
    """Compute current rx/tx Mbps for a lab from the two most recent samples."""
    samples = db.get_recent_system_samples(lab_id, count=2)
    if len(samples) < 2:
        return None
    cur, prev = samples[0], samples[1]
    try:
        t_cur = datetime.fromisoformat(cur["timestamp"])
        t_prev = datetime.fromisoformat(prev["timestamp"])
        delta_s = (t_cur - t_prev).total_seconds()
        if delta_s <= 0:
            return None
        cur_net = cur["data"].get("network", [])
        prev_net = prev["data"].get("network", [])
        prev_map = {n["interface"]: n for n in prev_net}
        rx_delta = tx_delta = 0
        for iface in cur_net:
            if iface.get("interface") == "lo":
                continue
            p = prev_map.get(iface["interface"], {})
            rx_delta += max(0, iface.get("bytes_recv", 0) - p.get("bytes_recv", 0))
            tx_delta += max(0, iface.get("bytes_sent", 0) - p.get("bytes_sent", 0))
        return {
            "rx": round(rx_delta * 8 / delta_s / 1_000_000, 2),
            "tx": round(tx_delta * 8 / delta_s / 1_000_000, 2),
        }
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Handler: Node inventory queries
# ---------------------------------------------------------------------------

_INVENTORY_PATTERN = re.compile(
    r"(?:how many|number of)\s+(?:nodes?|servers?|machines?|hosts?|labs?)"
    # "list [all|the|les|los|las|le|la|el|der|das|den] nodes" — tolerate
    # untranslated foreign articles that leak through multilingual norm.
    r"|list\s+(?:(?:all|the|les|los|las|le|la|el|der|das|den|dem|de)\s+)?(?:nodes?|servers?|machines?|hosts?|labs?)"
    # SOV-order languages (e.g. DE 'knoten auflisten' → 'node list'):
    r"|(?:nodes?|servers?|machines?|hosts?|labs?)\s+(?:list|show)\b"
    r"|(?:what|which)\s+(?:nodes?|servers?|machines?|hosts?|labs?)\s+(?:do i|do we|are there)"
    r"|(?:show|get|display)\s+(?:all\s+)?(?:nodes?|servers?|machines?|hosts?|labs?)"
    r"|(?:registered|enrolled|connected)\s+(?:nodes?|servers?|labs?)"
    r"|(?:my|our)\s+(?:nodes?|servers?)"
    # Bare 'node count' / 'host count' — no question framing needed
    r"|^\s*(?:node|host|server|lab)\s+count\s*$"
)


def _handle_inventory(question: str, match: re.Match) -> dict:
    """Handle: 'How many nodes?', 'List nodes', 'What nodes do I have?'"""
    labs = _scoped_list_labs()

    if not labs:
        return _build_response(
            answer=_t("inventory.none"),
            query_type="inventory",
            confidence=0.95,
            sources=[],
        )

    online_count = 0
    offline_count = 0
    plural = "s" if len(labs) != 1 else ""
    parts = [_t("inventory.header", n=len(labs), plural=plural)]

    for lab in labs:
        online = _lab_is_online(lab["last_seen"])
        if online:
            online_count += 1
            status = _t("inventory.state_online")
        else:
            offline_count += 1
            status = _t("inventory.state_offline")

        os_info = lab.get("os", "")
        arch = lab.get("arch", "")
        version = lab.get("agent_version", "")
        detail_parts = []
        if os_info:
            detail_parts.append(os_info)
        if arch:
            detail_parts.append(arch)
        if version:
            detail_parts.append(f"agent v{version}")
        detail = f" ({', '.join(detail_parts)})" if detail_parts else ""

        parts.append(
            _t(
                "inventory.line",
                hostname=lab["hostname"],
                state=status,
                detail=detail,
            )
        )

    parts.append("")
    parts.append(
        _t("inventory.footer", online=online_count, offline=offline_count)
    )

    return _build_response(
        answer="\n".join(parts),
        query_type="inventory",
        confidence=0.95,
        sources=[{"type": "fleet", "total": len(labs), "online": online_count, "offline": offline_count}],
    )


# ---------------------------------------------------------------------------
# Handler: Greetings & help (catches 'hello', 'hi', 'help', '?')
# ---------------------------------------------------------------------------

_GREETING_PATTERN = re.compile(
    r"^(?:hi|hey|hello|yo|sup|good (?:morning|afternoon|evening)|greetings|"
    r"help|halp|wat|what can (?:you|u) do|what do you do|"
    r"who are you|what are you)"
    r"(?:\s+(?:there|all|labwatch|bot|ember))?"
    r"\s*[!?.]*$"
)


def _handle_greeting(question: str, match: re.Match) -> dict:
    """Handle greetings and 'what can you do' style intros."""
    return _build_response(
        answer=_t("greeting.intro"),
        query_type="greeting",
        confidence=0.95,
        sources=[],
    )


# ---------------------------------------------------------------------------
# Handler: Generic health pulse (catches casual 'are we good', 'what's on fire')
# ---------------------------------------------------------------------------

_GENERIC_HEALTH_PATTERN = re.compile(
    r"(?:are\s+(?:we|things|we all)\s+(?:good|ok|okay|fine|alright))"
    r"|(?:everything\s+(?:good|ok|okay|fine|alright))"
    r"|(?:all\s+(?:good|ok|okay|fine|quiet|clear))"
    r"|(?:any(?:thing)?\s+on\s+fire)"
    r"|(?:what(?:'s|s|\sis)?\s+on\s+fire)"
    r"|(?:sanity\s+check)"
    r"|(?:gimme|give\s+me)\s+(?:a|the)\s+(?:pulse|sitrep|tldr|tl;dr)"
    r"|^(?:pulse|sitrep|tldr|tl;dr)\s*$"
)


def _handle_generic_health(question: str, match: re.Match) -> dict:
    """Casual health pulse — delegates to fleet overview but with casual prefix.

    Catches phrasings the fleet pattern misses ('are we good', 'sanity check').
    """
    fleet_response = _handle_fleet(question, match)
    # Re-tag so the miss-rate dashboard sees this as its own intent.
    fleet_response["query_type"] = "generic_health"
    return fleet_response


# ---------------------------------------------------------------------------
# Handler: How-do-I / docs pointer (catches 'how do i add a node', etc.)
# ---------------------------------------------------------------------------

_HOWTO_PATTERN = re.compile(
    r"(?:how (?:do|can) (?:i|we|u|you))\s+"
    r"(add|install|enroll|register|connect|set\s+up|setup|onboard|configure|silence|mute|update|upgrade|delete|remove)"
    r"|(?:how to)\s+"
    r"(add|install|enroll|register|connect|set\s+up|setup|onboard|configure|silence|mute|update|upgrade|delete|remove)"
    # SOV-order languages (after multilingual normalization): "how … add …"
    # where the action verb isn't adjacent to 'how'. Keeps the intent.
    r"|(?:\bhow\b[^?\n]{0,60}?\b(add|install|enroll|register|connect|configure|silence|mute|update|upgrade|delete|remove)\b)"
    r"|(?:where do i get|what is|where('s| is)) (?:the\s+)?(?:agent|install|signup|api|token|secret|docs|documentation)"
)


def _handle_howto(question: str, match: re.Match) -> dict:
    """Static help pointing users at the right docs page for common how-do-I questions.

    Routing on the (already-normalized) English keywords — the multilingual
    input normalizer translates foreign verbs like 'hinzufügen' / 'ajouter'
    / 'añadir' to their English canonical form before we get here.
    """
    q = question.lower()
    if any(w in q for w in ("add", "install", "enroll", "register", "connect", "onboard", "set up", "setup")):
        answer = _t("howto.add_node")
    elif any(w in q for w in ("silence", "mute")):
        answer = _t("howto.silence")
    elif any(w in q for w in ("delete", "remove")):
        answer = _t("howto.delete")
    elif any(w in q for w in ("update", "upgrade")):
        answer = _t("howto.update")
    elif "token" in q or "secret" in q:
        answer = _t("howto.token")
    else:
        answer = _t("howto.default")
    return _build_response(
        answer=answer,
        query_type="howto",
        confidence=0.85,
        sources=[],
    )


# ---------------------------------------------------------------------------
# Handler: Trends / forecasts / historical comparisons (honest decline)
# ---------------------------------------------------------------------------

_TREND_PATTERN = re.compile(
    r"(?:trend|trends|trending|history of|historical|over\s+(?:the\s+)?(?:last|past)\s+\d+\s+(?:day|week|month))"
    r"|(?:compare\b.{1,40}\b(?:vs|versus|to|against|with))"
    r"|(?:\b(?:today|yesterday|tomorrow)\s+(?:vs|versus|against|compared))"
    r"|(?:predict|forecast|projection|extrapolate|estimated|when will)"
    r"|(?:growth\s+rate|burn\s+rate)"
    r"|(?:yesterday(?:'s)?|last (?:night|week|month))\s+(?:cpu|memory|disk|alerts?|incidents?)"
)


def _handle_trend_decline(question: str, match: re.Match) -> dict:
    """Honest decline for trend/forecast queries we don't yet support.

    Pivots to the current snapshot so the user still gets value.
    """
    return _build_response(
        answer=_t("trend_decline.response"),
        query_type="trend_decline",
        confidence=0.9,
        sources=[],
    )


# ---------------------------------------------------------------------------
# Handler: Restart history (catches 'why did nginx restart', 'restart loop')
# ---------------------------------------------------------------------------

_RESTART_PATTERN = re.compile(
    r"(?:why\s+(?:did|does|is)\s+\S+\s+(?:restart|restarting|crash|crashing|die|dying))"
    r"|(?:restart\s+(?:loop|history|count))"
    r"|(?:in\s+(?:a\s+)?restart\s+loop)"
    r"|(?:which\s+container.*restart)"
    r"|(?:what.*restarting)"
    r"|(?:show.*restart(?:ing)?\s+containers?)"
    r"|(?:list.*restarting)"
    # Bare 'which node/container crashed last' / 'last crashed' / 'last to crash'
    r"|(?:(?:which|what)\s+(?:node|container|host|server|lab)?\s*crashed)"
    r"|(?:last\s+(?:to\s+)?(?:crash|restart))"
    r"|(?:crashed\s+last)"
)


def _handle_restart_history(question: str, match: re.Match) -> dict:
    """Show containers with non-zero restart_count, sorted by count."""
    labs = _scoped_list_labs()
    leaders = []
    for lab in labs:
        try:
            metrics = db.get_latest_metrics(lab["id"])
        except Exception:  # noqa: BLE001
            continue
        docker_data = (metrics or {}).get("docker") or {}
        containers = docker_data.get("containers") if isinstance(docker_data, dict) else None
        if not isinstance(containers, list):
            continue
        for c in containers:
            if not isinstance(c, dict):
                continue
            rc = c.get("restart_count") or 0
            if not isinstance(rc, (int, float)) or rc <= 0:
                continue
            leaders.append({
                "container": c.get("name") or "unknown",
                "restart_count": int(rc),
                "hostname": lab.get("hostname") or lab.get("id"),
            })
    leaders.sort(key=lambda x: x["restart_count"], reverse=True)

    if not leaders:
        return _build_response(
            answer=_t("restart_history.none"),
            query_type="restart_history",
            confidence=0.85,
            sources=[],
        )

    lines = [_t("restart_history.header", n=len(leaders))]
    for r in leaders[:10]:
        lines.append(
            _t(
                "restart_history.line",
                container=r["container"],
                hostname=r["hostname"],
                count=r["restart_count"],
            )
        )
    if len(leaders) > 10:
        lines.append(_t("restart_history.more", n=len(leaders) - 10))
    lines.append("")
    lines.append(_t("restart_history.footer"))
    return _build_response(
        answer="\n".join(lines),
        query_type="restart_history",
        confidence=0.9,
        sources=[{"type": "containers", "count": len(leaders)}],
    )


# ---------------------------------------------------------------------------
# Handler: Out-of-scope (jokes / weather / trivia / off-topic)
# ---------------------------------------------------------------------------
#
# We're a fleet monitor, not a general assistant. Owning that boundary
# politely is more honest than a generic "I didn't understand" — and stops
# the user from thinking we're broken when we just don't do that thing.
# ---------------------------------------------------------------------------

_OUT_OF_SCOPE_PATTERN = re.compile(
    r"(?:tell\s+(?:me\s+)?(?:a\s+)?joke|knock\s*knock|make\s+me\s+laugh|say\s+something\s+funny)"
    r"|(?:what(?:'s|\sis|s)?\s+(?:the\s+)?weather)"
    r"|(?:how(?:'s|\sis)?\s+(?:the\s+)?weather)"
    r"|(?:weather\s+(?:today|tomorrow|now|in|like))"
    r"|(?:what(?:'s|\sis|s)?\s+the\s+(?:time|date)\b)"
    r"|(?:tell\s+me\s+about\b(?=.{0,60}\b(?:weather|sun|moon|stars|planet|venus|mars|jupiter|saturn|space|universe|galaxy)\b))"
    r"|(?:what(?:'s|\sis|s)?\s+\d+\s*[\+\-\*\/x]\s*\d)"  # math like "what's 2+2"
    r"|(?:who\s+(?:is|was)\s+(?:the\s+)?(?:president|king|queen|prime\s+minister|pope|ceo))"
    r"|(?:capital\s+of\s+\w+)"
    r"|(?:meaning\s+of\s+life)"
    r"|(?:are\s+you\s+(?:human|real|conscious|alive|sentient))"
    r"|(?:do\s+you\s+(?:love|hate|like|enjoy|feel))"
    r"|(?:sing\s+(?:me\s+)?a\s+song)"
    r"|(?:write\s+(?:me\s+)?a\s+(?:poem|story|essay))"
)


def _handle_out_of_scope(question: str, match: re.Match) -> dict:
    """Polite decline for clearly off-topic queries."""
    return _build_response(
        answer=_t("out_of_scope.decline"),
        query_type="out_of_scope",
        confidence=0.9,
        sources=[],
    )


# ---------------------------------------------------------------------------
# Handler: Node capacity / plan limits ('how many more nodes can i add')
# ---------------------------------------------------------------------------

_NODE_CAPACITY_PATTERN = re.compile(
    r"(?:how\s+many\s+(?:more\s+)?(?:nodes?|hosts?|servers?|labs?)\s+can\s+i\s+(?:add|register|enroll))"
    r"|(?:can\s+i\s+add\s+(?:more|another)\s+(?:nodes?|hosts?|servers?))"
    r"|(?:(?:node|host|server|lab)\s+(?:limit|cap|quota|allowance))"
    r"|(?:my\s+(?:plan|tier)\s+(?:limit|cap|quota))"
    r"|(?:am\s+i\s+(?:at|over|near)\s+(?:my\s+)?(?:limit|cap|quota))"
)


def _handle_node_capacity(question: str, match: re.Match) -> dict:
    """Report current node count and the free-tier cap.

    Stripe / paid-tier upgrades aren't wired yet, so we report the free-tier
    cap honestly rather than pretending tier-aware logic exists.
    """
    labs = _scoped_list_labs()
    n = len(labs)
    free_cap = 3
    plural = "s" if n != 1 else ""
    if n >= free_cap:
        msg = _t("node_capacity.at_limit", n=n, cap=free_cap, plural=plural)
    else:
        remaining = free_cap - n
        msg = _t(
            "node_capacity.room",
            n=n,
            cap=free_cap,
            remaining=remaining,
            plural=plural,
        )
    return _build_response(
        answer=msg,
        query_type="node_capacity",
        confidence=0.9,
        sources=[{"type": "labs", "count": n}],
    )


# ---------------------------------------------------------------------------
# Fallback
# ---------------------------------------------------------------------------

def _fallback_response(question: str) -> dict:
    """Provide a helpful fallback when no pattern matches."""
    # Try to detect if it looks like a bare hostname (one token, no spaces).
    # Multi-word junk like "stautus of fleet" must NOT recurse into status —
    # _handle_status would strip back to empty and call us again.
    cleaned = question.strip().rstrip("?").strip()
    if cleaned and " " not in cleaned:
        lab = _find_lab(cleaned)
        if lab:
            fake_match = re.match(r"(.*)", cleaned)
            return _handle_status(cleaned, fake_match)

    return _build_response(
        answer=_t("fallback.intro"),
        query_type="fallback",
        confidence=0.0,
        sources=[],
    )


# ---------------------------------------------------------------------------
# Handler registry
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Slash commands — power-user shortcuts that bypass NL parsing.
# ---------------------------------------------------------------------------
# Triggered by any question starting with "/". Format: /<command> [args...]
# Supported:
#   /help                         list all commands
#   /cluster                      fleet overview (alias for "fleet status")
#   /cluster help                 show cluster-specific commands
#   /alerts [active|all]          recent alerts feed
#   /maintenance                  list labs currently in maintenance mode
#   /find                         hint about the ember mascot easter egg
#   /version                      labwatch version + lab count
# ---------------------------------------------------------------------------

_SLASH_HELP_TEXT = (
    "available slash commands:\n"
    "  /cluster              — fleet overview (status of every node)\n"
    "  /cluster help         — cluster-specific subcommands\n"
    "  /alerts               — recent alerts (active first)\n"
    "  /alerts active        — only currently firing alerts\n"
    "  /maintenance          — labs currently in maintenance mode\n"
    "  /find                 — hint about a hidden easter egg\n"
    "  /version              — labwatch version + visible lab count\n"
    "  /help                 — this list"
)

_CLUSTER_HELP_TEXT = (
    "cluster commands:\n"
    "  /cluster              — fleet status (online/offline/total)\n"
    "  /cluster help         — this help\n"
    "  /alerts               — show fleet alerts\n"
    "  /maintenance          — labs in maintenance mode\n"
    "tip: most natural-language questions also work — try \"which node uses the most cpu\""
)


def _slash_help(args: str) -> dict:
    if args.strip() == "cluster":
        return _build_response(_CLUSTER_HELP_TEXT, "slash_help", 1.0)
    return _build_response(_SLASH_HELP_TEXT, "slash_help", 1.0)


def _slash_cluster(args: str) -> dict:
    sub = args.strip().lower()
    if sub in ("help", "?", "-h", "--help"):
        return _build_response(_CLUSTER_HELP_TEXT, "slash_cluster_help", 1.0)
    # Default: fleet overview
    labs = _scoped_list_labs()
    if not labs:
        return _build_response(
            "no labs registered yet. install the agent: curl -fsSL https://labwatch.dev/install.sh | sudo bash",
            "slash_cluster", 1.0,
        )
    online = sum(1 for l in labs if _lab_is_online(l.get("last_seen")))
    offline = len(labs) - online
    lines = [f"cluster: {len(labs)} labs ({online} online, {offline} offline)"]
    for l in labs[:30]:
        is_on = _lab_is_online(l.get("last_seen"))
        dot = "●" if is_on else "○"
        name = l.get("display_name") or l.get("hostname", "?")
        lines.append(f"  {dot} {name}")
    if len(labs) > 30:
        lines.append(f"  …and {len(labs) - 30} more")
    return _build_response(
        "\n".join(lines),
        "slash_cluster",
        1.0,
        sources=[{"type": "labs", "count": len(labs)}],
    )


def _slash_alerts(args: str) -> dict:
    only_active = args.strip().lower() in ("active", "open", "firing")
    labs = {l["id"]: l for l in _scoped_list_labs()}
    if not labs:
        return _build_response("no labs to show alerts for.", "slash_alerts", 1.0)
    alerts = db.get_recent_alerts_feed(limit=20) if hasattr(db, "get_recent_alerts_feed") else []
    alerts = [a for a in alerts if a.get("lab_id") in labs]
    if only_active:
        alerts = [a for a in alerts if not a.get("resolved_at")]
    if not alerts:
        msg = "no active alerts — all clear." if only_active else "no recent alerts."
        return _build_response(msg, "slash_alerts", 1.0)
    lines = [f"recent alerts ({len(alerts)}):"]
    for a in alerts[:15]:
        sev = a.get("severity", "info")
        host = a.get("hostname", "?")
        msg = a.get("message", "")
        marker = "✓" if a.get("resolved_at") else "!"
        lines.append(f"  [{marker}] {sev:8} {host}: {msg}")
    return _build_response("\n".join(lines), "slash_alerts", 1.0,
                           sources=[{"type": "alerts", "count": len(alerts)}])


def _fmt_until_relative(iso_str: Optional[str]) -> str:
    """Format an ISO timestamp as a short relative duration (e.g. "2h 4m left")."""
    if not iso_str:
        return "no end time"
    try:
        dt = datetime.fromisoformat(iso_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        mins = int((dt - datetime.now(timezone.utc)).total_seconds() / 60)
        if mins <= 0:
            return "expired"
        if mins < 60:
            return f"{mins}m left"
        if mins < 60 * 24:
            return f"{mins // 60}h {mins % 60}m left"
        return f"{mins // (60 * 24)}d left"
    except (ValueError, TypeError):
        # Don't crash the whole slash command on one corrupt timestamp, but
        # make the bug greppable instead of silently showing garbage.
        logger.warning("malformed maintenance until timestamp: %r", iso_str)
        return iso_str[:16].replace("T", " ")


def _slash_maintenance(args: str) -> dict:
    labs = _scoped_list_labs()
    if not labs:
        return _build_response("no labs registered.", "slash_maintenance", 1.0)
    # Single bulk query instead of one DB round-trip per lab — stays cheap
    # as the fleet grows. db.list_active_maintenance applies the same
    # "enabled + within window" filter as db.get_active_maintenance_state.
    try:
        state_by_id = db.list_active_maintenance([lab["id"] for lab in labs])
    except Exception as e:
        logger.warning("maintenance bulk lookup failed: %s", e)
        state_by_id = {}
    in_maint = [(lab, state_by_id[lab["id"]]) for lab in labs if lab["id"] in state_by_id]
    if not in_maint:
        return _build_response("no labs are in maintenance mode.", "slash_maintenance", 1.0)
    lines = [f"labs in maintenance ({len(in_maint)}):"]
    for lab, state in in_maint:
        name = lab.get("display_name") or lab.get("hostname", "?")
        reason = state.get("reason") or "(no reason)"
        until_fmt = _fmt_until_relative(state.get("until"))
        lines.append(f"  • {name} — {reason} ({until_fmt})")
    return _build_response("\n".join(lines), "slash_maintenance", 1.0)


def _slash_find(args: str) -> dict:
    return _build_response(
        "ember is hiding. read the install script carefully — it's the kind of "
        "thing only curious people notice. first finder gets a free year.",
        "slash_find",
        1.0,
    )


def _slash_version(args: str) -> dict:
    labs = _scoped_list_labs()
    return _build_response(
        f"labwatch v0.1.0 — {len(labs)} lab{'s' if len(labs) != 1 else ''} visible",
        "slash_version",
        1.0,
    )


_SLASH_COMMANDS = {
    "help":        _slash_help,
    "?":           _slash_help,
    "cluster":     _slash_cluster,
    "fleet":       _slash_cluster,  # alias
    "alerts":      _slash_alerts,
    "maintenance": _slash_maintenance,
    "maint":       _slash_maintenance,  # alias
    "find":        _slash_find,
    "ember":       _slash_find,  # alias
    "version":     _slash_version,
}


def _try_slash_command(question: str) -> Optional[dict]:
    """Return a response dict if the question is a slash command, else None."""
    if not question.startswith("/"):
        return None
    body = question[1:].strip()
    if not body:
        return _slash_help("")
    parts = body.split(None, 1)
    cmd = parts[0].lower()
    args = parts[1] if len(parts) > 1 else ""
    handler = _SLASH_COMMANDS.get(cmd)
    if not handler:
        return _build_response(
            f"unknown command: /{cmd}\ntry /help",
            "slash_unknown",
            1.0,
        )
    return handler(args)



# Log retrieval queries
_LOG_PATTERN = re.compile(
    r"(?:show|get|display|view|pull|fetch)\s+(?:me\s+)?(?:the\s+)?logs?\s+(?:from|for|of|on)\s+(.+)"
    r"|logs?\s+(?:from|for|of|on)\s+(.+)"
    r"|(?:recent|latest|last)\s+(?:error\s+)?logs?"
    r"|(?:any|are\s+there)\s+(?:error|warning|critical)\s+logs?"
    r"|error\s+logs?"
)


def _handle_logs(question: str, match: re.Match) -> dict:
    """Handle: 'show logs from proxmox-01', 'recent error logs', 'any error logs?'"""
    # Try to extract a node name from the match groups
    target = match.group(1) or match.group(2) if match.lastindex and match.lastindex >= 1 else None

    if target:
        target = target.strip().rstrip("?. ")
        for noise in ["the", "my", "our", "server", "node"]:
            target = re.sub(r'\b' + noise + r'\b', '', target).strip()

    # Determine if it's an error-specific query
    is_error = bool(re.search(r'\b(?:error|warning|critical|fail)\b', question))

    labs = _scoped_list_labs()

    if target:
        lab = _find_lab(target)
        if not lab:
            return _build_response(
                answer=f"No node found matching \"{target}\". Available nodes: {', '.join(l['hostname'] for l in labs[:10])}.",
                query_type="logs",
                confidence=0.5,
                sources=[],
            )
        labs = [lab]

    if not labs:
        return _build_response(answer="No labs registered yet.", query_type="logs", confidence=0.9, sources=[])

    lines = []
    total_shown = 0
    max_per_node = 5 if len(labs) > 1 else 15

    for lab in labs[:5]:  # Limit to 5 nodes
        level_filter = "error" if is_error else None
        try:
            logs = db.get_logs(lab["id"], limit=max_per_node, level=level_filter)
        except Exception:
            continue

        if not logs:
            if len(labs) == 1:
                level_note = f" {level_filter}" if level_filter else ""
                lines.append(f"No{level_note} logs found for {lab['hostname']}.")
            continue

        lines.append(f"**{lab['hostname']}** ({len(logs)} recent{'  error' if is_error else ''} logs):")
        for log in logs:
            ts = log.get("ts", "")[:19]
            level = log.get("level", "info").upper()
            source = log.get("source", "")
            msg = log.get("message", "")[:120]
            lines.append(f"  [{ts}] {level} ({source}): {msg}")
            total_shown += 1
        lines.append("")

    if not lines:
        lines.append("No logs found across the fleet.")

    if total_shown > 0:
        lines.append(f"Showing {total_shown} log entries. Use the web UI for full log search with filters.")

    return _build_response(
        answer="\n".join(lines),
        query_type="logs",
        confidence=0.85,
        sources=[{"type": "logs", "nodes": len(labs)}],
    )


HANDLERS = [
    # Out-of-scope decline — first so jokes/weather/trivia don't accidentally
    # match a fleet/status keyword later in the pipeline.
    {"pattern": _OUT_OF_SCOPE_PATTERN, "func": _handle_out_of_scope, "name": "out_of_scope"},
    # Greetings / help intro — early so 'hello'/'help' don't match anything else
    {"pattern": _GREETING_PATTERN, "func": _handle_greeting, "name": "greeting"},
    # Node capacity / plan limits — before how-to so 'how many more nodes can i add'
    # doesn't get eaten by the howto pattern's 'add' branch.
    {"pattern": _NODE_CAPACITY_PATTERN, "func": _handle_node_capacity, "name": "node_capacity"},
    # How-do-I help — early so 'how do i add a node' doesn't get eaten by inventory
    {"pattern": _HOWTO_PATTERN, "func": _handle_howto, "name": "howto"},
    # Trend/forecast honest decline — before everything that mentions cpu/memory/alerts
    {"pattern": _TREND_PATTERN, "func": _handle_trend_decline, "name": "trend_decline"},
    # Restart history — before container/diagnostic which would otherwise eat 'why did X restart'
    {"pattern": _RESTART_PATTERN, "func": _handle_restart_history, "name": "restart_history"},
    # Alert queries — before fleet (more specific; "alerts" != "overview")
    {"pattern": _ALERT_PATTERN, "func": _handle_alerts, "name": "alerts"},
    # Attention/issues — before fleet (more specific; "any issues" != "overview")
    {"pattern": _ATTENTION_PATTERN, "func": _handle_attention, "name": "attention"},
    # Node inventory — before fleet ("list nodes" != "fleet overview")
    {"pattern": _INVENTORY_PATTERN, "func": _handle_inventory, "name": "inventory"},
    # Generic health pulse — before fleet so 'are we good' / 'sanity check' route here
    {"pattern": _GENERIC_HEALTH_PATTERN, "func": _handle_generic_health, "name": "generic_health"},
    # Fleet overview
    {"pattern": _FLEET_PATTERN, "func": _handle_fleet, "name": "fleet_overview"},
    # Time-range queries
    {"pattern": _TIME_PATTERN, "func": _handle_time, "name": "time_range"},
    # Temperature queries — before capacity (both mention "hot" / resource words)
    {"pattern": _TEMPERATURE_PATTERN, "func": _handle_temperature, "name": "temperature"},
    # Capacity/disk queries
    {"pattern": _CAPACITY_PATTERN, "func": _handle_capacity, "name": "capacity"},
    # Container queries — before comparative and status (prevents misrouting)
    {"pattern": _CONTAINER_PATTERN, "func": _handle_containers, "name": "containers"},
    # Network queries — before comparative ("network usage" != "which uses most")
    {"pattern": _NETWORK_PATTERN, "func": _handle_network, "name": "network"},
    # Comparative queries (try all patterns)
    {"pattern": _COMPARATIVE_PATTERN, "func": _handle_comparative, "name": "comparative"},
    {"pattern": _COMPARATIVE_ALT_PATTERN, "func": _handle_comparative, "name": "comparative_alt"},
    {"pattern": _COMPARATIVE_TOP_PATTERN, "func": _handle_comparative, "name": "comparative_top"},
    # Diagnostic queries
    {"pattern": _DIAGNOSTIC_PATTERN, "func": _handle_diagnostic, "name": "diagnostic"},
    # Log retrieval queries
    {"pattern": _LOG_PATTERN, "func": _handle_logs, "name": "logs"},
    # Status queries — last because pattern is broad
    {"pattern": _STATUS_PATTERN, "func": _handle_status, "name": "status"},
    {"pattern": _STATUS_SIMPLE_PATTERN, "func": _handle_status, "name": "status_simple"},
]


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def query(question: str, email: Optional[str] = None, lang: str = "en") -> dict:
    """Process a natural language question about the infrastructure.

    Args:
        question: Natural-language question about labs, metrics, alerts, etc.
        email: If set, scope all lab lookups to labs owned by this user.
               None (default) = global scope (admin context only).
        lang: Response locale ("en", "de", "fr", "es", "uk"). Unknown
               languages fall back to English. Input-side keyword
               normalization is language-agnostic.

    Returns:
        {
            "answer": str,      # Natural language response
            "sources": list,    # Data sources used
            "query_type": str,  # Matched query type
            "confidence": float # 0-1 confidence in the match
        }
    """
    if lang not in TEMPLATES:
        lang = "en"
    # Reject excessively long queries to prevent regex/processing abuse
    if len(question) > 2000:
        return _build_response(
            answer="Query too long. Please keep your question under 2000 characters.",
            query_type="error",
            confidence=1.0,
            sources=[],
        )
    token = _scope_email.set(email)
    locale_token = _nlq_locale.set(lang)
    try:
        question_stripped = question.strip()
        # Slash commands are case-sensitive in the command name only — keep original.
        slash_result = _try_slash_command(question_stripped)
        if slash_result is not None:
            return slash_result

        question_lower = question.lower().strip().rstrip("?")
        question_lower = _normalize_typos(question_lower)
        question_lower = _normalize_language(question_lower)

        # Try each handler in priority order
        result = None
        for handler in HANDLERS:
            match = handler["pattern"].search(question_lower)
            if match:
                try:
                    result = handler["func"](question_lower, match)
                except Exception as e:
                    logging.getLogger("labwatch").exception(f"NLQ handler error: {e}")
                    result = _build_response(
                        answer="Something went wrong processing your query. Please try rephrasing.",
                        query_type="error",
                        confidence=0.0,
                        sources=[],
                    )
                break

        if result is None:
            result = _fallback_response(question_lower)

        # Instrumentation: log every query so we can measure the fallback rate
        # and see what phrasings the regex engine is missing. Non-fatal.
        try:
            import database
            qtype = result.get("query_type", "unknown")
            matched = qtype not in ("fallback", "error")
            database.log_nlq_query(
                question=question_stripped,
                query_type=qtype,
                matched=matched,
                confidence=float(result.get("confidence", 0.0) or 0.0),
                email=email,
            )
        except Exception:
            pass

        return result
    finally:
        _scope_email.reset(token)
        _nlq_locale.reset(locale_token)
