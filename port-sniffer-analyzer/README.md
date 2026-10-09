# Port Sniffer & Packet Analyzer

Outil Python d'**analyse réseau autorisée** : un scanner de ports TCP asynchrone et un analyseur de paquets en direct (Scapy), réunis derrière une interface web FastAPI mono-page et responsive.

> ⚠️ **Usage légal** — Cet outil ne doit être utilisé que sur des réseaux que vous possédez ou pour lesquels vous disposez d'une autorisation écrite explicite. Le périmètre autorisé est volontairement restreint par défaut (loopback et adresses privées). Aucune fonction d'exploitation, de paiement ou d'achat n'est incluse.

---

## Sommaire

- [Fonctionnalités](#fonctionnalités)
- [Modèle de sécurité](#modèle-de-sécurité)
- [Architecture du projet](#architecture-du-projet)
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Lancement](#lancement)
- [Configuration](#configuration)
- [Utilisation de l'interface](#utilisation-de-linterface)
- [Référence API](#référence-api)
- [Détail interne des modules](#détail-interne-des-modules)
- [Tests](#tests)
- [Limitations et notes](#limitations-et-notes)
- [Dépannage](#dépannage)

---

## Fonctionnalités

### 1. Scanner de ports
- Scan TCP **connect** asynchrone (pas de scan furtif half-open), donc **aucun privilège requis**.
- Résolution DNS puis vérification de périmètre avant tout envoi de paquet.
- Détection des états : `open`, `closed`, `filtered`, `error`.
- **Banner grabbing** : lecture du message d'accueil (SSH, FTP, SMTP…), et envoi automatique d'une requête `HEAD / HTTP/1.0` sur les ports web (80, 8000, 8008, 8080, 8888, 5000, 3000, 9000) qui restent silencieux.
- Mesure de la **latence** (ms) par port, noms de service via `socket.getservbyport`.
- Spécification des ports : preset `top`, `all`, ou liste/plages `22,80,8000-8100`.
- Concurrence bornée et configurable (jusqu'à 1000 connexions simultanées).

### 2. Analyseur de paquets
- Capture live via **Scapy** dans un thread d'arrière-plan (nécessite root ou `CAP_NET_RAW`).
- Décodage : **Ethernet, ARP, IPv4, IPv6, TCP (drapeaux), UDP, ICMP, DNS**.
- Buffer circulaire borné des **5000 derniers paquets** (mémoire stabilisée).
- Statistiques : total paquets/octets, débit (paquets/s), répartition par protocole, **top talkers** (10), **top flows** (10).
- **Séries temporelles** par seconde pour les graphiques (fenêtre jusqu'à 600 s).
- Détail d'un paquet : couches, en-têtes MAC, drapeaux TCP et **hexdump** Scapy complet.
- **Export `.pcap`** du buffer courant (téléchargeable depuis l'UI).
- Filtre **BPF** optionnel et choix de l'interface.

### 3. Interface web
- Dashboard sombre responsive en **un seul fichier** (`psa/static/index.html`), sans build ni dépendance front.
- Bilingue **français / anglais** (bascule persistée dans `localStorage`).
- Graphiques temps réel dessinés en Canvas (paquets/s, débit, protocoles) avec survol interactif.
- Bannière de verdict, résumé coloré, historique des 5 derniers scans.
- Notifications toast, animations respectant `prefers-reduced-motion`.

---

## Modèle de sécurité

- **Périmètre par défaut** : boucle locale et adresses privées uniquement :
  - IPv4 : `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`
  - IPv6 : `::1/128`, `fc00::/7` (ULA), `fe80::/10` (link-local)
- **Anti-DNS-rebinding** : un nom d'hôte est résolu **une seule fois**, chaque adresse obtenue est validée, puis le scan utilise **l'IP vérifiée** — jamais une re-résolution du nom.
- Toute adresse hors périmètre renvoie **HTTP 403**.
- Les bannières distantes sont **non fiables** : nettoyées côté serveur (caractères non imprimables repliés, tronquées à 200 caractères) et échappées côté client (`esc()`), prévenant les injections.
- L'extension du périmètre est explicite via variable d'environnement (voir [Configuration](#configuration)).

---

## Architecture du projet

```
port-sniffer-analyzer/
├── psa/
│   ├── __init__.py        # Numéro de version (__version__ = "1.0.0")
│   ├── scope.py           # Périmètre, résolution de cible, parsing des ports
│   ├── scanner.py         # Scanner TCP asynchrone + banner grabbing
│   ├── analyzer.py        # Thread de capture Scapy, décodage, statistiques
│   ├── app.py             # Application FastAPI : routes REST + montage UI
│   └── static/
│       └── index.html     # Frontend complet (HTML + CSS + JS inline)
├── tests/
│   ├── __init__.py
│   ├── test_scope.py      # Périmètre et parsing des ports
│   ├── test_scanner.py    # Scan réel sur loopback + nettoyage de bannières
│   ├── test_analyzer.py   # Décodage de paquets, buffer, séries temporelles
│   └── test_api.py        # Endpoints FastAPI via TestClient
├── requirements.txt
└── README.md
```

Flux de données :

```
Navigateur ──HTTP──▶ FastAPI (app.py)
                        │
                        ├─▶ scope.py   : valide cible + parse ports
                        ├─▶ scanner.py : scan asyncio ──▶ résultats JSON
                        └─▶ analyzer.py: thread Scapy ──▶ buffer mémoire
                                                          │
                              status / timeseries / packets / export.pcap
```

---

## Prérequis

- **Python 3.10+** (le code utilise `X | Y`, `asyncio.timeout` moderne, etc. ; testé sous 3.13).
- Pour la **capture de paquets** : droits `root` ou la capacité `CAP_NET_RAW` (Linux).
- Le **scanner de ports** fonctionne sans privilège particulier.

---

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Dépendances (`requirements.txt`) :

| Paquet | Rôle |
|--------|------|
| `fastapi` | Framework web / API |
| `uvicorn[standard]` | Serveur ASGI |
| `scapy` | Capture et décodage de paquets |
| `pydantic` | Validation des corps de requête |
| `pytest` | Tests (dev) |
| `httpx` | Client HTTP pour les tests d'API |

---

## Lancement

```bash
# Mode scan seul (sans privilèges) — l'onglet analyseur restera sans capture
uvicorn psa.app:app --host 0.0.0.0 --port 8000

# Mode complet avec capture de paquets (root)
sudo .venv/bin/uvicorn psa.app:app --host 0.0.0.0 --port 8000
```

Puis ouvrez <http://localhost:8000>.

**Alternative sans root sur Linux** (grant de capacité) :

```bash
sudo setcap cap_net_raw,cap_net_admin+eip "$(readlink -f "$(which python3)")"
```

Documentation interactive auto-générée : `http://localhost:8000/docs` (Swagger UI) et `/redoc`.

---

## Configuration

| Variable d'environnement | Effet | Exemple |
|--------------------------|-------|---------|
| `PSA_ALLOWED_NETWORKS` | Ajoute des réseaux au périmètre autorisé (séparés par des virgules). À n'utiliser que pour des réseaux que vous êtes autorisé à tester. | `export PSA_ALLOWED_NETWORKS="203.0.113.0/24,2001:db8:1::/48"` |

> Le périmètre est chargé **une fois au démarrage** (`ALLOWED_NETWORKS = load_allowed_networks()`), donc un redémarrage est nécessaire après modification.

Constantes internes notables :

| Constante | Valeur | Module |
|-----------|--------|--------|
| `MAX_HOSTNAME_LEN` | 253 | `scope.py` |
| `MAX_PORTS_PER_SCAN` | 65535 | `scope.py` |
| `MAX_CONCURRENCY` | 1000 | `scanner.py` |
| `BANNER_BYTES` | 256 | `scanner.py` |
| Buffer de capture | 5000 paquets | `analyzer.py` (`CaptureManager(max_packets=5000)`) |
| `SERIES_SECONDS` | 600 | `analyzer.py` |

---

## Utilisation de l'interface

### Onglet « Scanner de ports »
1. Choisissez une cible (IP ou nom d'hôte) — un raccourci **Ma machine** préremplit `127.0.0.1`.
2. Indiquez les ports (`top`, `all`, ou `22,80,8000-8100`).
3. Réglez le délai max (0.2–10 s), le parallélisme (1–1000) et la lecture des bannières.
4. Cliquez sur **Lancer le scan**. Une animation radar s'affiche pendant l'analyse.
5. Le résultat présente un verdict, un résumé (ouverts / filtrés / erreurs / fermés / scannés) et un tableau détaillé. Les ports fermés sont omis du tableau mais comptés dans le résumé.

### Onglet « Analyseur de paquets »
1. Sélectionnez l'**interface** et un éventuel **filtre BPF** (ex. `tcp port 443`).
2. Cliquez sur **Démarrer l'écoute**. Sans privilèges, l'UI affiche une erreur explicite.
3. Suivez en direct : compteurs, graphiques (paquets/s, débit, protocoles), top talkers et flux.
4. Cliquez une ligne de paquet pour voir ses **couches et son hexdump**.
5. **Exporter .pcap** télécharge le buffer courant au format pcap.

---

## Référence API

### `GET /api/health`
État du service, version, privilèges et périmètre autorisé.

```json
{
  "status": "ok",
  "version": "1.0.0",
  "privileged": false,
  "allowed_networks": ["127.0.0.0/8", "::1/128", "10.0.0.0/8", "..."]
}
```

### `POST /api/scan`
Lance un scan TCP.

Corps (`ScanRequest`) :

| Champ | Type | Défaut | Contraintes |
|-------|------|--------|-------------|
| `target` | string | — | 1–253 caractères |
| `ports` | string | `"top"` | max 2000 caractères ; `top`, `all`, ou liste/plages |
| `timeout` | float | `1.0` | 0.2–10.0 |
| `concurrency` | int | `300` | 1–1000 |
| `banners` | bool | `true` | lecture des bannières |

```bash
curl -X POST http://localhost:8000/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"target":"127.0.0.1","ports":"22,80,8000-8100","timeout":1,"banners":true}'
```

Réponse :

```json
{
  "target": "127.0.0.1",
  "address": "127.0.0.1",
  "addresses": ["127.0.0.1"],
  "ports_scanned": 105,
  "duration_ms": 43.2,
  "summary": {"open": 1, "closed": 104, "filtered": 0, "error": 0},
  "results": [
    {"port": 22, "state": "open", "service": "ssh", "banner": "SSH-2.0-OpenSSH_9.6", "latency_ms": 0.31}
  ]
}
```

Codes d'erreur : **403** cible hors périmètre, **400** erreur de saisie (ports/target), **422** validation Pydantic.

### `GET /api/interfaces`
Liste des interfaces de capture (`{"interfaces": [...], "privileged": bool}`).

### `POST /api/capture/start` — `201 Created`
Démarre la capture.

Corps (`CaptureStart`) : `{"iface": "eth0" | null, "bpf": "tcp port 443" | null}`.

Erreurs : **409** capture déjà active, **400** interface inconnue, **403** problème de privilèges (`PermissionError`), **500** autre erreur (interface/BPF invalide).

### `POST /api/capture/stop`
Arrête la capture et renvoie les statistiques.

### `GET /api/capture/status`
Statistiques courantes.

```json
{
  "running": true,
  "iface": "eth0",
  "bpf": "tcp port 443",
  "error": null,
  "started_at": 1759999999.0,
  "total_packets": 1234,
  "total_bytes": 987654,
  "distinct_talkers": 17,
  "packets_per_sec": 12.5,
  "protocols": {"TCP": 900, "UDP": 300, "DNS": 34},
  "top_talkers": [["10.0.0.5", 400]],
  "top_flows": [["10.0.0.5:51000 → 10.0.0.1:443 (TCP)", 220]]
}
```

### `GET /api/capture/timeseries?window=120`
Séries par seconde. `window` entre **10 et 600** (défaut 120), **422** hors bornes.

```json
{
  "now": 1759999999,
  "window": 120,
  "points": [{"t": 1759999880, "packets": 5, "bytes": 1200, "protocols": {"TCP": 5}}]
}
```
Les secondes sans trafic sont **remplies à zéro** pour garantir une courbe continue.

### `GET /api/capture/packets?since=N&limit=500`
Paquets d'`id` strictement supérieur à `since`. `limit` de 1 à 2000.

### `GET /api/capture/packets/{id}`
Détail d'un paquet (couches, MAC, drapeaux, hexdump). **404** si l'id a été évincé du buffer.

### `GET /api/capture/export.pcap`
Télécharge le buffer au format pcap (`application/vnd.tcpdump.pcap`). Le fichier temporaire est supprimé automatiquement après envoi.

### `GET /`
Sert l'interface statique (`StaticFiles` monté en dernier pour laisser la priorité aux routes API).

---

## Détail interne des modules

### `psa/scope.py`
- `load_allowed_networks()` : construit la liste des réseaux depuis `DEFAULT_NETWORKS` + `PSA_ALLOWED_NETWORKS`.
- `resolve_target()` : accepte un littéral IP ou un nom d'hôte (résolution `getaddrinfo` en TCP, déduplication, suppression de la zone IPv6 `%`).
- `check_target()` : vérifie que **chaque** adresse résolue appartient au périmètre ; lève `ScopeError` sinon.
- `parse_ports()` : gère `top`/vide (preset `TOP_PORTS`), `all` (1–65535), les listes et plages ; déduplique et trie ; borne à `MAX_PORTS_PER_SCAN`.

### `psa/scanner.py`
- Dataclass `PortResult` (`port`, `state`, `service`, `banner`, `latency_ms`).
- `clean_banner()` : décode en UTF-8 (erreurs remplacées), remplace les caractères non imprimables par des espaces, compacte les blancs, tronque à 200 caractères.
- `_grab_banner()` : lecture du greeting ; sur port « HTTP-like » silencieux, envoi d'une requête `HEAD`.
- `probe_port()` : `asyncio.open_connection` avec sémaphore et timeout ; classifie `filtered` (timeout), `closed` (refus), `error` (autre OSError), `open`.
- `scan_host()` : crée le sémaphore (borné par `MAX_CONCURRENCY`), lance toutes les sondes via `asyncio.gather`, renvoie trié par port.

### `psa/analyzer.py`
- `decode_packet()` : convertit un paquet Scapy en enregistrement JSON (ARP prioritaire, puis IPv4/IPv6, TCP/UDP/ICMP, puis ré-étiquetage DNS si `DNSQR` présent).
- `CaptureManager` :
  - `start()` / `stop()` pilotent un thread daemon exécutant `sniff(... store=False, timeout=1)` en boucle.
  - `_handle()` (sous verrou) : assigne un id croissant, alimente buffers de records/bruts, compteurs (`protocols`, `talkers`, `flows`, totaux) et buckets par seconde.
  - `timeseries()` : fenêtre glissante, remplissage à zéro, bornée à `SERIES_SECONDS`.
  - `packets_since()`, `packet_detail()`, `stats()`, `export_pcap()` (`wrpcap`).
- `list_interfaces()` : via `scapy.arch.get_if_list()`, retourne `[]` en cas d'échec.
- `is_privileged()` : `os.geteuid() == 0`.

### `psa/static/index.html`
- Aucun framework : JavaScript vanilla organisé par sections (i18n, helpers, onglets, scanner, graphiques, analyseur).
- `api()` centralise les appels `fetch` et la gestion d'erreurs (statut HTTP, message de détail).
- `LiveChart` : classe de rendu Canvas avec easings, gestion HiDPI, tooltip au survol, axes auto-échelonnés (`niceCeil`).
- `renderScan()` : verdict + résumé + tableau, avec compteurs animés.
- Historique des scans et préférence de langue stockés dans `localStorage` (`psaHistory`, `psaLang`).
- Sécurité XSS : tout contenu distant passe par `esc()` avant insertion HTML.

---

## Tests

```bash
pytest -q
```

État actuel : **35 tests passent** (suite `tests/`).

Couverture fonctionnelle :
- `test_scope.py` : périmètre par défaut, refus des adresses publiques, extension par variable d'environnement, cible vide/irrésolvable, parsing des ports valides/invalides/presets.
- `test_scanner.py` : nettoyage des bannières, détection open/closed + bannière sur un vrai serveur loopback, sonde HTTP `HEAD`.
- `test_analyzer.py` : décodage TCP/ARP/UDP/DNS/ICMP/IPv6, buffer circulaire et évictions, statistiques, séries temporelles et remplissage à zéro.
- `test_api.py` : health, refus hors périmètre (403), ports invalides (400), scan loopback, service de l'UI, endpoints packets/timeseries.

---

## Limitations et notes

- Le scan est un **TCP connect scan** : il établit de vraies connexions, donc il est visible côté cible et adapté à un usage autorisé plutôt qu'à un audit furtif.
- La capture conserve les **5000 derniers paquets** ; les statistiques cumulées continuent de croître même quand la fenêtre de détail évince les anciens paquets.
- Le buffer et les compteurs sont **remis à zéro à chaque `capture/start`**.
- La capture est **mono-instance** : une seule capture à la fois par processus (verrou `running`).
- Aucune authentification : **n'exposez pas ce service sur une interface publique**. Réservez-le à `localhost` ou à un réseau de confiance.
- `PSA_ALLOWED_NETWORKS` n'est lu qu'au démarrage.
- Les buckets de séries sont indexés par seconde murale ; un long `timeout` de `sniff` n'affecte pas leur finesse (timeout fixé à 1 s).

---

## Dépannage

| Symptôme | Cause probable | Solution |
|----------|----------------|----------|
| `403` sur un scan | Cible hors périmètre | Ajoutez le réseau à `PSA_ALLOWED_NETWORKS` si vous êtes autorisé, puis redémarrez |
| Capture refusée (`403`) | Pas de droits réseau | Lancez avec `sudo`, ou appliquez `setcap cap_net_raw,cap_net_admin+eip` |
| Aucune interface listée | Scapy indisponible / droits | Vérifiez l'installation de Scapy et les privilèges |
| `400 Unknown interface` | Interface inconnue | Rechargez la liste des interfaces dans l'UI |
| `500` au démarrage capture | Filtre BPF ou interface invalide | Corrigez le filtre BPF ou choisissez une autre interface |
| `404` sur un paquet | Id évincé du buffer | Le paquet est plus ancien que les 5000 derniers |
| Aucun paquet alors que ça tourne | Pas de trafic / filtre trop strict | Élargissez ou retirez le filtre BPF |
