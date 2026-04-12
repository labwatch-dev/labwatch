"""Multilingual response templates for the NLQ engine (Phase 2).

Stored as a flat Python dict-of-dicts instead of JSON so handlers can pull
the catalog in one import and format templates with named variables via
`str.format(**kwargs)`. English is the source of truth and every other
language falls back to it automatically via `nlq._t()`.

Keys are namespaced by handler:
    greeting.intro                 — _handle_greeting full body
    fallback.intro                 — _fallback_response full body
    howto.add_node                 — _handle_howto (add/install branch)
    howto.silence                  — _handle_howto (silence/mute branch)
    howto.delete                   — _handle_howto (delete/remove branch)
    howto.update                   — _handle_howto (update/upgrade branch)
    howto.token                    — _handle_howto (token/secret branch)
    howto.default                  — _handle_howto (docs pointer default)
    out_of_scope.decline           — _handle_out_of_scope
    trend_decline.response         — _handle_trend_decline
    status_no_target.response      — _handle_status when no node name extracted
    generic_health.ok              — (reserved for future casual-pulse phrasing)
    node_capacity.at_limit         — at/over free-tier cap
    node_capacity.room             — still has room on free tier
    restart_history.none           — no container restarts in retention window
    status.online_state            — single word "online"
    status.offline_state           — single word "OFFLINE"
    status.host_state              — "{hostname} is {state}."
    status.metric_line             — "CPU {cpu}%, Memory {mem}%, Disk {disk}%."
    status.load_line               — "Load average {load}."
    status.uptime_line             — "Uptime: {uptime}."
    status.containers_line         — "{running}/{total} containers running."
    status.alerts_line             — "{total} active alert(s) ({breakdown})."
    status.alerts_latest           — "Latest: {message}"
    status.no_alerts               — "No active alerts."
    status.last_seen_minutes       — "Last seen {n} minutes ago."
    status.last_seen_hours         — "Last seen {n} hours ago."
    status.last_seen_days          — "Last seen {n} days ago."
    status.last_seen_unknown       — "Last seen time unknown."
    status.alert_critical          — "{n} critical"
    status.alert_warning           — "{n} warning"
    inventory.none                 — "No nodes registered yet..."
    inventory.header                — "{n} registered node(s):"
    inventory.line                 — "  - {hostname}: {state}{detail}"
    inventory.footer               — "{online} online, {offline} offline."
    inventory.state_online         — "ONLINE"
    inventory.state_offline        — "OFFLINE"
    container_status.not_found     — "Could not find '{name}' as a registered node or running container."

Only hand-authored translations are stored here. Formatting placeholders
(named vars) are identical across languages. When adding a new key,
always add an English entry first, then the translations.
"""

TEMPLATES: dict[str, dict[str, str]] = {
    "en": {
        "greeting.intro": (
            "hi — I'm labwatch. ask me about your fleet in plain english. things i understand:\n"
            "  - 'fleet status' / 'how's everything' / 'are we good'\n"
            "  - 'is pve-storage ok' / 'how hot is pve'\n"
            "  - 'show me alerts' / 'what needs attention'\n"
            "  - 'which container uses the most cpu'\n"
            "  - 'how do i add a node'\n"
            "  - try /help for slash commands"
        ),
        "fallback.intro": (
            "I'm not sure how to answer that. Try asking things like:\n"
            "  - \"How's my lab?\"\n"
            "  - \"Is pve-storage okay?\"\n"
            "  - \"Show me all alerts\"\n"
            "  - \"What containers are running?\"\n"
            "  - \"How hot is pve-storage?\"\n"
            "  - \"What needs attention?\"\n"
            "  - \"How many nodes do I have?\"\n"
            "  - \"Which node uses the most CPU?\"\n"
            "  - \"Which container uses the most memory?\"\n"
            "  - \"What's the network usage?\"\n"
            "  - \"What happened last night?\"\n"
            "  - \"Am I running out of disk space?\"\n"
            "  - \"Why is pve-storage slow?\"\n"
            "  - \"Give me a summary\""
        ),
        "howto.add_node": (
            "to add a node: log in → /my/add-node → click 'generate install command' → "
            "copy the one-line curl into your node's terminal as root. the agent installs, "
            "writes its config, and starts itself. see /docs for the long version."
        ),
        "howto.silence": (
            "to silence alerts on a node: open the node's detail page → 'maintenance mode' → "
            "set a duration. or use the /maintenance slash command to see what's currently silenced."
        ),
        "howto.delete": (
            "to remove a node: /my/dashboard → click the node → 'delete' at the bottom. "
            "this also deletes its metrics and alerts."
        ),
        "howto.update": (
            "to update an agent: re-run the install one-liner from /my/add-node — it overwrites "
            "the binary and restarts the systemd service. config is preserved."
        ),
        "howto.token": (
            "your agent token is shown once at signup and on /my/add-node. it's also in the "
            "agent's config.yaml on the node. lost it? regenerate from the node's detail page."
        ),
        "howto.default": (
            "the docs live at /docs and the self-hosting guide at /self-hosted. "
            "for slash commands, try /help."
        ),
        "out_of_scope.decline": (
            "i'm a fleet monitor — i don't do jokes, weather, trivia, or general chat. "
            "ask me about your nodes, containers, alerts, or metrics. "
            "try 'fleet status' or 'help' to see what i can answer."
        ),
        "trend_decline.response": (
            "i don't track historical trends or forecasts yet — the current build holds "
            "metrics for a rolling retention window (default 24h on free, longer on paid) "
            "and gives you live state, not time-series. "
            "for the current picture try 'fleet status' or 'what needs attention'."
        ),
        "status_no_target.response": (
            "I couldn't tell which node you're asking about. Try a hostname "
            "like 'pve-storage status' or 'how's pve-docker'."
        ),
        "node_capacity.at_limit": (
            "you currently have {n} node{plural} registered. "
            "the free tier is capped at {cap}. "
            "paid tiers (homelab/pro/business) unlock more — see /#pricing."
        ),
        "node_capacity.room": (
            "you have {n} node{plural} registered. "
            "free tier allows up to {cap}, so you can add {remaining} more "
            "on the current plan. for higher limits see /#pricing."
        ),
        "restart_history.none": (
            "no containers have restarted in the current retention window — "
            "everything looks stable. (note: i only see restart counts since the "
            "agent was last restarted; older incidents fall outside retention.)"
        ),
        "restart_history.header": "containers with restarts ({n} total):",
        "restart_history.line": "  • {container} on {hostname} — {count}×",
        "restart_history.more": "  ...and {n} more.",
        "restart_history.footer": (
            "i don't track per-restart timestamps yet, so i can't say *why* it restarted — "
            "check the agent's docker collector or the container's own logs for that."
        ),
        # Status handler fragments
        "status.state_online": "online",
        "status.state_offline": "OFFLINE",
        "status.host_state": "{hostname} is {state}.",
        "status.metric_line": "CPU {cpu:.1f}%, Memory {mem:.1f}%, Disk {disk:.1f}%.",
        "status.load_line": "Load average {load:.2f}.",
        "status.uptime_line": "Uptime: {uptime}.",
        "status.containers_line": "{running}/{total} containers running.",
        "status.gpu_line": "{name}: {util:.0f}% util, {vram:.0f}% VRAM, {temp:.0f}°C.",
        "status.last_seen_minutes": "Last seen {n} minutes ago.",
        "status.last_seen_hours": "Last seen {n:.1f} hours ago.",
        "status.last_seen_days": "Last seen {n:.1f} days ago.",
        "status.last_seen_unknown": "Last seen time unknown.",
        "status.alert_critical": "{n} critical",
        "status.alert_warning": "{n} warning",
        "status.alerts_line": "{count} active alert{plural} ({breakdown}).",
        "status.alerts_latest": "Latest: {message}",
        "status.no_alerts": "No active alerts.",
        # Inventory
        "inventory.none": "No nodes registered yet. Install the labwatch agent on a machine to get started.",
        "inventory.header": "{n} registered node{plural}:",
        "inventory.line": "  - {hostname}: {state}{detail}",
        "inventory.footer": "{online} online, {offline} offline.",
        "inventory.state_online": "ONLINE",
        "inventory.state_offline": "OFFLINE",
        "container_status.not_found": "Could not find '{name}' as a registered node or running container.",
        # Fleet overview
        "fleet.no_labs": "No labs registered yet. Install the agent on a machine to get started.",
        "fleet.summary_line": "{total} node{total_plural}, {online} online. {alerts} active alert{alerts_plural}. {health}",
        "fleet.health_healthy": "All systems healthy.",
        "fleet.health_critical": "Needs attention — {n} critical alert{plural}.",
        "fleet.health_degraded": "Degraded — {n} node{plural} offline.",
        "fleet.health_mostly_healthy": "Mostly healthy — {n} active warning{plural}.",
        "fleet.health_normal": "Running normally.",
        "fleet.offline_line": "Offline: {nodes}.",
        "fleet.breakdown_header": "Per-node breakdown:",
        "fleet.node_line": "  {hostname}: {status} — CPU {cpu:.0f}%, MEM {mem:.0f}%, DISK {disk:.0f}%{extras}",
        "fleet.node_status_ok": "OK",
        "fleet.node_status_alert": "ALERT",
        "fleet.node_status_offline": "OFFLINE",
        "fleet.extra_gpu": ", GPU {util:.0f}%/{temp:.0f}°C",
        "fleet.extra_containers": ", {n} containers",
        "fleet.extra_alerts": ", {n} alert{plural}",
        # Simple reusable state words (for future reuse in other handlers)
        "common.online": "online",
        "common.offline": "offline",
        "common.critical": "critical",
        "common.warning": "warning",
        "common.unknown": "unknown",
    },

    "de": {
        "greeting.intro": (
            "hi — ich bin labwatch. frag mich auf deutsch (oder englisch) nach deiner flotte. was ich verstehe:\n"
            "  - 'flottenstatus' / 'wie läuft alles' / 'alles gut'\n"
            "  - 'ist pve-storage ok' / 'wie heiß ist pve'\n"
            "  - 'zeig mir warnungen' / 'was braucht aufmerksamkeit'\n"
            "  - 'welcher container nutzt am meisten cpu'\n"
            "  - 'wie füge ich einen knoten hinzu'\n"
            "  - probier /help für slash-befehle"
        ),
        "fallback.intro": (
            "Ich weiß nicht, wie ich das beantworten soll. Versuch Fragen wie:\n"
            "  - \"Wie geht's meiner Flotte?\"\n"
            "  - \"Ist pve-storage ok?\"\n"
            "  - \"Zeig mir alle Warnungen\"\n"
            "  - \"Welche Container laufen?\"\n"
            "  - \"Wie heiß ist pve-storage?\"\n"
            "  - \"Was braucht Aufmerksamkeit?\"\n"
            "  - \"Wie viele Knoten habe ich?\"\n"
            "  - \"Welcher Knoten nutzt am meisten CPU?\"\n"
            "  - \"Welcher Container nutzt am meisten Speicher?\"\n"
            "  - \"Wie ist die Netzwerkauslastung?\"\n"
            "  - \"Was ist letzte Nacht passiert?\"\n"
            "  - \"Geht mir der Speicherplatz aus?\"\n"
            "  - \"Warum ist pve-storage langsam?\"\n"
            "  - \"Gib mir eine Zusammenfassung\""
        ),
        "howto.add_node": (
            "um einen knoten hinzuzufügen: einloggen → /my/add-node → 'install-befehl generieren' klicken → "
            "den einzeiligen curl-befehl als root auf dem knoten ausführen. der agent installiert sich, "
            "schreibt seine konfiguration und startet selbst. siehe /docs für die ausführliche anleitung."
        ),
        "howto.silence": (
            "um warnungen auf einem knoten stummzuschalten: detailseite des knotens öffnen → 'wartungsmodus' → "
            "dauer festlegen. oder /maintenance nutzen, um zu sehen, was aktuell stumm ist."
        ),
        "howto.delete": (
            "um einen knoten zu entfernen: /my/dashboard → auf den knoten klicken → 'löschen' unten. "
            "metriken und warnungen werden ebenfalls gelöscht."
        ),
        "howto.update": (
            "um einen agent zu aktualisieren: den install-einzeiler von /my/add-node erneut ausführen — "
            "er überschreibt die binary und startet den systemd-dienst neu. die konfiguration bleibt erhalten."
        ),
        "howto.token": (
            "dein agent-token wird einmal bei der registrierung und auf /my/add-node angezeigt. er steht auch "
            "in der config.yaml des agents auf dem knoten. verloren? auf der detailseite des knotens neu generieren."
        ),
        "howto.default": (
            "die docs findest du auf /docs und den self-hosting-guide auf /self-hosted. "
            "für slash-befehle probier /help."
        ),
        "out_of_scope.decline": (
            "ich bin ein flotten-monitor — ich mache keine witze, kein wetter, keine trivia, keinen smalltalk. "
            "frag mich nach deinen knoten, containern, warnungen oder metriken. "
            "probier 'flottenstatus' oder 'help', um zu sehen, was ich beantworten kann."
        ),
        "trend_decline.response": (
            "ich verfolge noch keine historischen trends oder prognosen — der aktuelle build speichert "
            "metriken in einem rollierenden retention-fenster (standard 24h bei free, länger bei paid) "
            "und liefert dir live-status, keine zeitreihen. "
            "für den aktuellen stand probier 'flottenstatus' oder 'was braucht aufmerksamkeit'."
        ),
        "status_no_target.response": (
            "Ich konnte nicht erkennen, nach welchem Knoten du fragst. Versuch einen Hostnamen "
            "wie 'pve-storage status' oder 'wie ist pve-docker'."
        ),
        "node_capacity.at_limit": (
            "du hast aktuell {n} knoten registriert. "
            "der free-tier ist auf {cap} begrenzt. "
            "bezahlte tiers (homelab/pro/business) schalten mehr frei — siehe /#pricing."
        ),
        "node_capacity.room": (
            "du hast {n} knoten registriert. "
            "free-tier erlaubt bis zu {cap}, du kannst also noch {remaining} hinzufügen "
            "auf dem aktuellen plan. für höhere limits siehe /#pricing."
        ),
        "restart_history.none": (
            "keine container haben im aktuellen retention-fenster neu gestartet — "
            "alles stabil. (hinweis: ich sehe restart-zähler nur seit dem letzten "
            "agent-neustart; ältere vorfälle fallen aus der retention.)"
        ),
        "restart_history.header": "container mit neustarts ({n} insgesamt):",
        "restart_history.line": "  • {container} auf {hostname} — {count}×",
        "restart_history.more": "  ...und {n} weitere.",
        "restart_history.footer": (
            "ich verfolge noch keine einzel-restart-zeitstempel, also kann ich nicht sagen *warum* neu gestartet wurde — "
            "prüf dafür den docker-collector des agents oder die logs des containers selbst."
        ),
        "status.state_online": "online",
        "status.state_offline": "OFFLINE",
        "status.host_state": "{hostname} ist {state}.",
        "status.metric_line": "CPU {cpu:.1f}%, Arbeitsspeicher {mem:.1f}%, Festplatte {disk:.1f}%.",
        "status.load_line": "Lastdurchschnitt {load:.2f}.",
        "status.uptime_line": "Laufzeit: {uptime}.",
        "status.containers_line": "{running}/{total} Container laufen.",
        "status.gpu_line": "{name}: {util:.0f}% Auslastung, {vram:.0f}% VRAM, {temp:.0f}°C.",
        "status.last_seen_minutes": "Zuletzt gesehen vor {n} Minuten.",
        "status.last_seen_hours": "Zuletzt gesehen vor {n:.1f} Stunden.",
        "status.last_seen_days": "Zuletzt gesehen vor {n:.1f} Tagen.",
        "status.last_seen_unknown": "Letzter Kontakt unbekannt.",
        "status.alert_critical": "{n} kritisch",
        "status.alert_warning": "{n} Warnung",
        "status.alerts_line": "{count} aktive Warnung{plural} ({breakdown}).",
        "status.alerts_latest": "Neueste: {message}",
        "status.no_alerts": "Keine aktiven Warnungen.",
        "inventory.none": "Noch keine Knoten registriert. Installier den labwatch-Agent auf einer Maschine, um loszulegen.",
        "inventory.header": "{n} registrierte Knoten:",
        "inventory.line": "  - {hostname}: {state}{detail}",
        "inventory.footer": "{online} online, {offline} offline.",
        "inventory.state_online": "ONLINE",
        "inventory.state_offline": "OFFLINE",
        "container_status.not_found": "Konnte '{name}' weder als registrierten Knoten noch als laufenden Container finden.",
        "fleet.no_labs": "Noch keine Labs registriert. Installier den Agent auf einer Maschine, um loszulegen.",
        "fleet.summary_line": "{total} Knoten, {online} online. {alerts} aktive Warnungen. {health}",
        "fleet.health_healthy": "Alle Systeme gesund.",
        "fleet.health_critical": "Braucht Aufmerksamkeit — {n} kritische Warnungen.",
        "fleet.health_degraded": "Beeinträchtigt — {n} Knoten offline.",
        "fleet.health_mostly_healthy": "Grösstenteils gesund — {n} aktive Warnungen.",
        "fleet.health_normal": "Läuft normal.",
        "fleet.offline_line": "Offline: {nodes}.",
        "fleet.breakdown_header": "Pro-Knoten-Übersicht:",
        "fleet.node_line": "  {hostname}: {status} — CPU {cpu:.0f}%, RAM {mem:.0f}%, Disk {disk:.0f}%{extras}",
        "fleet.node_status_ok": "OK",
        "fleet.node_status_alert": "WARNUNG",
        "fleet.node_status_offline": "OFFLINE",
        "fleet.extra_gpu": ", GPU {util:.0f}%/{temp:.0f}°C",
        "fleet.extra_containers": ", {n} Container",
        "fleet.extra_alerts": ", {n} Warnungen",
        "common.online": "online",
        "common.offline": "offline",
        "common.critical": "kritisch",
        "common.warning": "Warnung",
        "common.unknown": "unbekannt",
    },

    "fr": {
        "greeting.intro": (
            "salut — je suis labwatch. pose-moi des questions sur ta flotte en français (ou anglais). ce que je comprends :\n"
            "  - 'statut de la flotte' / 'comment ça va' / 'tout va bien'\n"
            "  - 'est-ce que pve-storage va bien' / 'à quelle température est pve'\n"
            "  - 'montre-moi les alertes' / 'qu'est-ce qui a besoin d'attention'\n"
            "  - 'quel conteneur utilise le plus de cpu'\n"
            "  - 'comment ajouter un nœud'\n"
            "  - essaie /help pour les commandes slash"
        ),
        "fallback.intro": (
            "Je ne sais pas comment répondre. Essaie des questions comme :\n"
            "  - \"Comment va ma flotte ?\"\n"
            "  - \"Est-ce que pve-storage va bien ?\"\n"
            "  - \"Montre-moi toutes les alertes\"\n"
            "  - \"Quels conteneurs tournent ?\"\n"
            "  - \"À quelle température est pve-storage ?\"\n"
            "  - \"Qu'est-ce qui a besoin d'attention ?\"\n"
            "  - \"Combien de nœuds j'ai ?\"\n"
            "  - \"Quel nœud utilise le plus de CPU ?\"\n"
            "  - \"Quel conteneur utilise le plus de mémoire ?\"\n"
            "  - \"Quelle est l'utilisation du réseau ?\"\n"
            "  - \"Qu'est-ce qui s'est passé la nuit dernière ?\"\n"
            "  - \"Est-ce que je manque d'espace disque ?\"\n"
            "  - \"Pourquoi pve-storage est lent ?\"\n"
            "  - \"Donne-moi un résumé\""
        ),
        "howto.add_node": (
            "pour ajouter un nœud : connecte-toi → /my/add-node → clique 'générer la commande d'installation' → "
            "copie la commande curl d'une ligne dans le terminal de ton nœud en root. l'agent s'installe, "
            "écrit sa config et démarre tout seul. voir /docs pour la version longue."
        ),
        "howto.silence": (
            "pour silencer les alertes sur un nœud : ouvre la page détail du nœud → 'mode maintenance' → "
            "définis une durée. ou utilise la commande /maintenance pour voir ce qui est actuellement silencé."
        ),
        "howto.delete": (
            "pour supprimer un nœud : /my/dashboard → clique sur le nœud → 'supprimer' en bas. "
            "les métriques et alertes sont aussi supprimées."
        ),
        "howto.update": (
            "pour mettre à jour un agent : relance la commande d'installation depuis /my/add-node — "
            "elle réécrit le binaire et redémarre le service systemd. la config est préservée."
        ),
        "howto.token": (
            "ton token d'agent est affiché une fois à l'inscription et sur /my/add-node. il est aussi dans "
            "le config.yaml de l'agent sur le nœud. perdu ? régénère-le depuis la page détail du nœud."
        ),
        "howto.default": (
            "les docs sont sur /docs et le guide d'auto-hébergement sur /self-hosted. "
            "pour les commandes slash, essaie /help."
        ),
        "out_of_scope.decline": (
            "je suis un moniteur de flotte — je ne fais pas de blagues, de météo, de trivia ou de bavardage. "
            "pose-moi des questions sur tes nœuds, conteneurs, alertes ou métriques. "
            "essaie 'statut de la flotte' ou 'help' pour voir ce que je peux répondre."
        ),
        "trend_decline.response": (
            "je ne suis pas encore les tendances historiques ou les prévisions — la version actuelle garde "
            "les métriques dans une fenêtre de rétention glissante (24h par défaut en free, plus long en payant) "
            "et te donne l'état en direct, pas de séries temporelles. "
            "pour l'état actuel, essaie 'statut de la flotte' ou 'qu'est-ce qui a besoin d'attention'."
        ),
        "status_no_target.response": (
            "Je n'ai pas pu identifier le nœud dont tu parles. Essaie un nom d'hôte "
            "comme 'pve-storage status' ou 'comment va pve-docker'."
        ),
        "node_capacity.at_limit": (
            "tu as actuellement {n} nœud{plural} enregistré{plural}. "
            "le tier gratuit est plafonné à {cap}. "
            "les tiers payants (homelab/pro/business) en débloquent plus — voir /#pricing."
        ),
        "node_capacity.room": (
            "tu as {n} nœud{plural} enregistré{plural}. "
            "le tier gratuit autorise jusqu'à {cap}, donc tu peux en ajouter {remaining} de plus "
            "sur le plan actuel. pour des limites plus hautes, voir /#pricing."
        ),
        "restart_history.none": (
            "aucun conteneur n'a redémarré dans la fenêtre de rétention actuelle — "
            "tout est stable. (note : je ne vois les compteurs de redémarrage que depuis "
            "le dernier redémarrage de l'agent ; les incidents plus anciens sortent de la rétention.)"
        ),
        "restart_history.header": "conteneurs avec redémarrages ({n} au total) :",
        "restart_history.line": "  • {container} sur {hostname} — {count}×",
        "restart_history.more": "  ...et {n} de plus.",
        "restart_history.footer": (
            "je ne suis pas encore les timestamps par redémarrage, donc je ne peux pas dire *pourquoi* ça a redémarré — "
            "vérifie le collector docker de l'agent ou les logs du conteneur lui-même pour ça."
        ),
        "status.state_online": "en ligne",
        "status.state_offline": "HORS LIGNE",
        "status.host_state": "{hostname} est {state}.",
        "status.metric_line": "CPU {cpu:.1f}%, Mémoire {mem:.1f}%, Disque {disk:.1f}%.",
        "status.load_line": "Charge moyenne {load:.2f}.",
        "status.uptime_line": "Uptime : {uptime}.",
        "status.containers_line": "{running}/{total} conteneurs en cours d'exécution.",
        "status.gpu_line": "{name} : {util:.0f}% util, {vram:.0f}% VRAM, {temp:.0f}°C.",
        "status.last_seen_minutes": "Vu pour la dernière fois il y a {n} minutes.",
        "status.last_seen_hours": "Vu pour la dernière fois il y a {n:.1f} heures.",
        "status.last_seen_days": "Vu pour la dernière fois il y a {n:.1f} jours.",
        "status.last_seen_unknown": "Dernière vue inconnue.",
        "status.alert_critical": "{n} critique",
        "status.alert_warning": "{n} avertissement",
        "status.alerts_line": "{count} alerte{plural} active{plural} ({breakdown}).",
        "status.alerts_latest": "Dernière : {message}",
        "status.no_alerts": "Pas d'alertes actives.",
        "inventory.none": "Aucun nœud enregistré pour l'instant. Installe l'agent labwatch sur une machine pour commencer.",
        "inventory.header": "{n} nœud{plural} enregistré{plural} :",
        "inventory.line": "  - {hostname} : {state}{detail}",
        "inventory.footer": "{online} en ligne, {offline} hors ligne.",
        "inventory.state_online": "EN LIGNE",
        "inventory.state_offline": "HORS LIGNE",
        "container_status.not_found": "Impossible de trouver '{name}' comme nœud enregistré ou conteneur en cours d'exécution.",
        "fleet.no_labs": "Aucun lab enregistré pour l'instant. Installe l'agent sur une machine pour commencer.",
        "fleet.summary_line": "{total} nœud{total_plural}, {online} en ligne. {alerts} alerte{alerts_plural} active{alerts_plural}. {health}",
        "fleet.health_healthy": "Tous les systèmes sont sains.",
        "fleet.health_critical": "Nécessite de l'attention — {n} alerte{plural} critique{plural}.",
        "fleet.health_degraded": "Dégradé — {n} nœud{plural} hors ligne.",
        "fleet.health_mostly_healthy": "Globalement sain — {n} avertissement{plural} actif{plural}.",
        "fleet.health_normal": "Fonctionnement normal.",
        "fleet.offline_line": "Hors ligne : {nodes}.",
        "fleet.breakdown_header": "Détail par nœud :",
        "fleet.node_line": "  {hostname} : {status} — CPU {cpu:.0f}%, MÉM {mem:.0f}%, DISQUE {disk:.0f}%{extras}",
        "fleet.node_status_ok": "OK",
        "fleet.node_status_alert": "ALERTE",
        "fleet.node_status_offline": "HORS LIGNE",
        "fleet.extra_gpu": ", GPU {util:.0f}%/{temp:.0f}°C",
        "fleet.extra_containers": ", {n} conteneurs",
        "fleet.extra_alerts": ", {n} alerte{plural}",
        "common.online": "en ligne",
        "common.offline": "hors ligne",
        "common.critical": "critique",
        "common.warning": "avertissement",
        "common.unknown": "inconnu",
    },

    "es": {
        "greeting.intro": (
            "hola — soy labwatch. pregúntame sobre tu flota en español (o inglés). lo que entiendo:\n"
            "  - 'estado de la flota' / 'cómo va todo' / 'todo bien'\n"
            "  - '¿está ok pve-storage?' / '¿cómo de caliente está pve?'\n"
            "  - 'muéstrame las alertas' / 'qué necesita atención'\n"
            "  - 'qué contenedor usa más cpu'\n"
            "  - 'cómo añadir un nodo'\n"
            "  - prueba /help para comandos slash"
        ),
        "fallback.intro": (
            "No sé cómo responder a eso. Prueba preguntas como:\n"
            "  - \"¿Cómo está mi laboratorio?\"\n"
            "  - \"¿Está bien pve-storage?\"\n"
            "  - \"Muéstrame todas las alertas\"\n"
            "  - \"¿Qué contenedores están corriendo?\"\n"
            "  - \"¿Qué tan caliente está pve-storage?\"\n"
            "  - \"¿Qué necesita atención?\"\n"
            "  - \"¿Cuántos nodos tengo?\"\n"
            "  - \"¿Qué nodo usa más CPU?\"\n"
            "  - \"¿Qué contenedor usa más memoria?\"\n"
            "  - \"¿Cuál es el uso de red?\"\n"
            "  - \"¿Qué pasó anoche?\"\n"
            "  - \"¿Se me está acabando el espacio en disco?\"\n"
            "  - \"¿Por qué está lento pve-storage?\"\n"
            "  - \"Dame un resumen\""
        ),
        "howto.add_node": (
            "para añadir un nodo: inicia sesión → /my/add-node → haz clic en 'generar comando de instalación' → "
            "copia el curl de una línea al terminal de tu nodo como root. el agente se instala, "
            "escribe su configuración y se inicia solo. mira /docs para la versión larga."
        ),
        "howto.silence": (
            "para silenciar alertas en un nodo: abre la página de detalle del nodo → 'modo mantenimiento' → "
            "define una duración. o usa el comando /maintenance para ver qué está silenciado actualmente."
        ),
        "howto.delete": (
            "para eliminar un nodo: /my/dashboard → haz clic en el nodo → 'eliminar' abajo. "
            "esto también elimina sus métricas y alertas."
        ),
        "howto.update": (
            "para actualizar un agente: vuelve a ejecutar el comando de instalación desde /my/add-node — "
            "sobrescribe el binario y reinicia el servicio systemd. la configuración se conserva."
        ),
        "howto.token": (
            "tu token de agente se muestra una vez al registrarte y en /my/add-node. también está en "
            "el config.yaml del agente en el nodo. ¿lo perdiste? regenéralo desde la página de detalle del nodo."
        ),
        "howto.default": (
            "la documentación está en /docs y la guía de auto-hospedaje en /self-hosted. "
            "para comandos slash, prueba /help."
        ),
        "out_of_scope.decline": (
            "soy un monitor de flota — no hago chistes, clima, trivia ni charla general. "
            "pregúntame sobre tus nodos, contenedores, alertas o métricas. "
            "prueba 'estado de la flota' o 'help' para ver qué puedo responder."
        ),
        "trend_decline.response": (
            "todavía no sigo tendencias históricas ni pronósticos — la build actual guarda "
            "métricas en una ventana de retención rodante (24h por defecto en free, más tiempo en pago) "
            "y te da el estado en vivo, no series temporales. "
            "para la imagen actual prueba 'estado de la flota' o 'qué necesita atención'."
        ),
        "status_no_target.response": (
            "No pude identificar de qué nodo estás preguntando. Prueba un hostname "
            "como 'pve-storage status' o 'cómo está pve-docker'."
        ),
        "node_capacity.at_limit": (
            "actualmente tienes {n} nodo{plural} registrado{plural}. "
            "el tier gratuito está limitado a {cap}. "
            "los tiers pagos (homelab/pro/business) desbloquean más — ver /#pricing."
        ),
        "node_capacity.room": (
            "tienes {n} nodo{plural} registrado{plural}. "
            "el tier gratuito permite hasta {cap}, así que puedes añadir {remaining} más "
            "en el plan actual. para límites más altos ver /#pricing."
        ),
        "restart_history.none": (
            "ningún contenedor se ha reiniciado en la ventana de retención actual — "
            "todo estable. (nota: solo veo los contadores de reinicio desde el "
            "último reinicio del agente; los incidentes más antiguos caen fuera de la retención.)"
        ),
        "restart_history.header": "contenedores con reinicios ({n} en total):",
        "restart_history.line": "  • {container} en {hostname} — {count}×",
        "restart_history.more": "  ...y {n} más.",
        "restart_history.footer": (
            "todavía no sigo timestamps por reinicio, así que no puedo decir *por qué* se reinició — "
            "revisa el collector docker del agente o los logs del propio contenedor para eso."
        ),
        "status.state_online": "en línea",
        "status.state_offline": "FUERA DE LÍNEA",
        "status.host_state": "{hostname} está {state}.",
        "status.metric_line": "CPU {cpu:.1f}%, Memoria {mem:.1f}%, Disco {disk:.1f}%.",
        "status.load_line": "Carga promedio {load:.2f}.",
        "status.uptime_line": "Uptime: {uptime}.",
        "status.containers_line": "{running}/{total} contenedores corriendo.",
        "status.gpu_line": "{name}: {util:.0f}% util, {vram:.0f}% VRAM, {temp:.0f}°C.",
        "status.last_seen_minutes": "Visto por última vez hace {n} minutos.",
        "status.last_seen_hours": "Visto por última vez hace {n:.1f} horas.",
        "status.last_seen_days": "Visto por última vez hace {n:.1f} días.",
        "status.last_seen_unknown": "Última vez visto desconocido.",
        "status.alert_critical": "{n} crítica",
        "status.alert_warning": "{n} advertencia",
        "status.alerts_line": "{count} alerta{plural} activa{plural} ({breakdown}).",
        "status.alerts_latest": "Última: {message}",
        "status.no_alerts": "Sin alertas activas.",
        "inventory.none": "Aún no hay nodos registrados. Instala el agente de labwatch en una máquina para empezar.",
        "inventory.header": "{n} nodo{plural} registrado{plural}:",
        "inventory.line": "  - {hostname}: {state}{detail}",
        "inventory.footer": "{online} en línea, {offline} fuera de línea.",
        "inventory.state_online": "EN LÍNEA",
        "inventory.state_offline": "FUERA DE LÍNEA",
        "container_status.not_found": "No se pudo encontrar '{name}' como nodo registrado o contenedor en ejecución.",
        "fleet.no_labs": "Aún no hay labs registrados. Instala el agente en una máquina para empezar.",
        "fleet.summary_line": "{total} nodo{total_plural}, {online} en línea. {alerts} alerta{alerts_plural} activa{alerts_plural}. {health}",
        "fleet.health_healthy": "Todos los sistemas sanos.",
        "fleet.health_critical": "Necesita atención — {n} alerta{plural} crítica{plural}.",
        "fleet.health_degraded": "Degradado — {n} nodo{plural} fuera de línea.",
        "fleet.health_mostly_healthy": "Mayormente sano — {n} advertencia{plural} activa{plural}.",
        "fleet.health_normal": "Funcionando normalmente.",
        "fleet.offline_line": "Fuera de línea: {nodes}.",
        "fleet.breakdown_header": "Desglose por nodo:",
        "fleet.node_line": "  {hostname}: {status} — CPU {cpu:.0f}%, MEM {mem:.0f}%, DISCO {disk:.0f}%{extras}",
        "fleet.node_status_ok": "OK",
        "fleet.node_status_alert": "ALERTA",
        "fleet.node_status_offline": "FUERA DE LÍNEA",
        "fleet.extra_gpu": ", GPU {util:.0f}%/{temp:.0f}°C",
        "fleet.extra_containers": ", {n} contenedores",
        "fleet.extra_alerts": ", {n} alerta{plural}",
        "common.online": "en línea",
        "common.offline": "fuera de línea",
        "common.critical": "crítica",
        "common.warning": "advertencia",
        "common.unknown": "desconocido",
    },

    "uk": {
        "greeting.intro": (
            "привіт — я labwatch. питай мене про твою флоту українською (або англійською). що я розумію:\n"
            "  - 'статус флоти' / 'як справи' / 'все добре'\n"
            "  - 'чи ок pve-storage' / 'наскільки гарячий pve'\n"
            "  - 'покажи попередження' / 'що потребує уваги'\n"
            "  - 'який контейнер використовує найбільше cpu'\n"
            "  - 'як додати вузол'\n"
            "  - спробуй /help для slash-команд"
        ),
        "fallback.intro": (
            "Я не знаю, як на це відповісти. Спробуй питання на кшталт:\n"
            "  - \"Як моя лабораторія?\"\n"
            "  - \"Чи ок pve-storage?\"\n"
            "  - \"Покажи всі попередження\"\n"
            "  - \"Які контейнери працюють?\"\n"
            "  - \"Наскільки гарячий pve-storage?\"\n"
            "  - \"Що потребує уваги?\"\n"
            "  - \"Скільки у мене вузлів?\"\n"
            "  - \"Який вузол використовує найбільше CPU?\"\n"
            "  - \"Який контейнер використовує найбільше пам'яті?\"\n"
            "  - \"Яке використання мережі?\"\n"
            "  - \"Що сталося минулої ночі?\"\n"
            "  - \"Чи закінчується місце на диску?\"\n"
            "  - \"Чому pve-storage повільний?\"\n"
            "  - \"Дай мені підсумок\""
        ),
        "howto.add_node": (
            "щоб додати вузол: увійди → /my/add-node → натисни 'згенерувати команду встановлення' → "
            "скопіюй однорядковий curl у термінал свого вузла як root. агент встановиться, "
            "запише свою конфігурацію та запуститься. дивись /docs для розгорнутої версії."
        ),
        "howto.silence": (
            "щоб заглушити попередження на вузлі: відкрий сторінку деталей вузла → 'режим обслуговування' → "
            "встанови тривалість. або використай команду /maintenance, щоб побачити, що зараз заглушено."
        ),
        "howto.delete": (
            "щоб видалити вузол: /my/dashboard → клікни на вузол → 'видалити' внизу. "
            "це також видаляє його метрики та попередження."
        ),
        "howto.update": (
            "щоб оновити агента: повторно запусти однорядкову команду встановлення з /my/add-node — "
            "вона перезаписує бінарник і перезапускає сервіс systemd. конфігурація зберігається."
        ),
        "howto.token": (
            "твій токен агента показується один раз при реєстрації та на /my/add-node. він також є в "
            "config.yaml агента на вузлі. втратив? перегенеруй зі сторінки деталей вузла."
        ),
        "howto.default": (
            "документація на /docs, а гайд з самохостингу на /self-hosted. "
            "для slash-команд спробуй /help."
        ),
        "out_of_scope.decline": (
            "я монітор флоти — я не роблю жартів, погоди, трівіа чи загальних розмов. "
            "питай мене про твої вузли, контейнери, попередження чи метрики. "
            "спробуй 'статус флоти' або 'help', щоб побачити, на що я можу відповісти."
        ),
        "trend_decline.response": (
            "я ще не відстежую історичні тренди чи прогнози — поточна збірка зберігає "
            "метрики в ковзному вікні ретенції (за замовчуванням 24г на free, довше на paid) "
            "і дає тобі живий стан, а не часові ряди. "
            "для поточної картини спробуй 'статус флоти' або 'що потребує уваги'."
        ),
        "status_no_target.response": (
            "Я не зміг зрозуміти, про який вузол ти питаєш. Спробуй хостнейм "
            "на кшталт 'pve-storage status' або 'як pve-docker'."
        ),
        "node_capacity.at_limit": (
            "у тебе зараз зареєстровано {n} вузлів. "
            "free-tier обмежений {cap}. "
            "платні тарифи (homelab/pro/business) відкривають більше — дивись /#pricing."
        ),
        "node_capacity.room": (
            "у тебе зареєстровано {n} вузлів. "
            "free-tier дозволяє до {cap}, тож ти можеш додати ще {remaining} "
            "на поточному плані. для вищих лімітів дивись /#pricing."
        ),
        "restart_history.none": (
            "жоден контейнер не перезапускався у поточному вікні ретенції — "
            "все стабільно. (нотатка: я бачу лічильники перезапуску лише з моменту "
            "останнього перезапуску агента; старіші інциденти випадають з ретенції.)"
        ),
        "restart_history.header": "контейнери з перезапусками ({n} всього):",
        "restart_history.line": "  • {container} на {hostname} — {count}×",
        "restart_history.more": "  ...і ще {n}.",
        "restart_history.footer": (
            "я ще не відстежую часові мітки окремих перезапусків, тож не можу сказати *чому* він перезапустився — "
            "перевір docker-колектор агента або логи самого контейнера для цього."
        ),
        "status.state_online": "онлайн",
        "status.state_offline": "ОФЛАЙН",
        "status.host_state": "{hostname} {state}.",
        "status.metric_line": "CPU {cpu:.1f}%, Пам'ять {mem:.1f}%, Диск {disk:.1f}%.",
        "status.load_line": "Середнє навантаження {load:.2f}.",
        "status.uptime_line": "Uptime: {uptime}.",
        "status.containers_line": "{running}/{total} контейнерів працює.",
        "status.gpu_line": "{name}: {util:.0f}% util, {vram:.0f}% VRAM, {temp:.0f}°C.",
        "status.last_seen_minutes": "Востаннє бачив {n} хвилин тому.",
        "status.last_seen_hours": "Востаннє бачив {n:.1f} годин тому.",
        "status.last_seen_days": "Востаннє бачив {n:.1f} днів тому.",
        "status.last_seen_unknown": "Час останнього контакту невідомий.",
        "status.alert_critical": "{n} критичних",
        "status.alert_warning": "{n} попереджень",
        "status.alerts_line": "{count} активних попереджень ({breakdown}).",
        "status.alerts_latest": "Останнє: {message}",
        "status.no_alerts": "Активних попереджень немає.",
        "inventory.none": "Ще немає зареєстрованих вузлів. Встанови labwatch-агент на машину, щоб почати.",
        "inventory.header": "{n} зареєстрованих вузлів:",
        "inventory.line": "  - {hostname}: {state}{detail}",
        "inventory.footer": "{online} онлайн, {offline} офлайн.",
        "inventory.state_online": "ОНЛАЙН",
        "inventory.state_offline": "ОФЛАЙН",
        "container_status.not_found": "Не вдалося знайти '{name}' ні як зареєстрований вузол, ні як запущений контейнер.",
        "fleet.no_labs": "Ще немає зареєстрованих лабів. Встанови агент на машину, щоб почати.",
        "fleet.summary_line": "{total} вузлів, {online} онлайн. {alerts} активних попереджень. {health}",
        "fleet.health_healthy": "Всі системи в порядку.",
        "fleet.health_critical": "Потребує уваги — {n} критичних попереджень.",
        "fleet.health_degraded": "Деградовано — {n} вузлів офлайн.",
        "fleet.health_mostly_healthy": "Переважно в порядку — {n} активних попереджень.",
        "fleet.health_normal": "Працює нормально.",
        "fleet.offline_line": "Офлайн: {nodes}.",
        "fleet.breakdown_header": "Розбивка по вузлах:",
        "fleet.node_line": "  {hostname}: {status} — CPU {cpu:.0f}%, ПАМ {mem:.0f}%, ДИСК {disk:.0f}%{extras}",
        "fleet.node_status_ok": "OK",
        "fleet.node_status_alert": "ТРИВОГА",
        "fleet.node_status_offline": "ОФЛАЙН",
        "fleet.extra_gpu": ", GPU {util:.0f}%/{temp:.0f}°C",
        "fleet.extra_containers": ", {n} контейнерів",
        "fleet.extra_alerts": ", {n} попереджень",
        "common.online": "онлайн",
        "common.offline": "офлайн",
        "common.critical": "критичний",
        "common.warning": "попередження",
        "common.unknown": "невідомо",
    },
}
