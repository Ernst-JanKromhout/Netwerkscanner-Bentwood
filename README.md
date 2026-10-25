# Netwerkscanner-Bentwood

Home Assistant-add-on die het thuisnetwerk volgt en meldt wat er verandert: nieuwe apparaten,
nieuwe of gesloten poorten, verdwenen apparaten. Je krijgt direct een pushmelding bij iets
urgents en elke ochtend een dagrapport.

Wat de add-on precies doet en welke opties er zijn, staat in [netwerkscanner/DOCS.md](netwerkscanner/DOCS.md).

## Installeren

Reken op een kwartier. Je hebt nodig: beheerrechten in UniFi en in Home Assistant.

### 1. UniFi-account met alleen leesrechten

1. Open UniFi (de Cloud Key, `https://192.168.1.227`).
2. Ga naar **Admins & Users → Create New**.
3. Vink **Restrict to local access only** aan.
4. Kies bij **Network** de rol **View Only**.
5. Noteer de gebruikersnaam en het wachtwoord. Die vul je in stap 4 in.

### 2. Uitzondering in IDS/IPS

De Gateway Max ziet poortscans anders als aanval en blokkeert ze.

1. Ga in UniFi Network naar **Settings → CyberSecure → Intrusion Prevention**.
2. Voeg het IP-adres van Home Assistant (`192.168.1.253`) toe aan de uitzonderingen.
   De precieze naam van die lijst verschilt per UniFi-versie.

### 3. Repository toevoegen in Home Assistant

De repository moet **openbaar** zijn. Een privé-repository kan Home Assistant niet ophalen.

1. Ga in Home Assistant naar **Instellingen → Apps** (in oudere versies: *Add-ons*).
2. Klik rechtsonder op **App installeren**.
3. Klik rechtsboven op **⋮ → Repositories**.
4. Plak `https://github.com/Ernst-JanKromhout/Netwerkscanner-Bentwood` en klik op **Toevoegen**, daarna op **Sluiten**.
5. Ververs de pagina (F5). Onderaan staat nu het blok *Netwerkscanner Bentwood*.

Let op: voeg de repository **niet** toe in HACS. HACS is alleen voor integraties en kaarten,
niet voor add-ons.

### 4. Installeren en instellen

1. Klik op **Netwerkscanner** en daarna op **Installeren**. Je Home Assistant bouwt de add-on zelf.
   Dat duurt een paar minuten.
2. Open het tabblad **Configuratie** en vul `unifi_username` en `unifi_password` in.
   Controleer `notify_services`: daar staat de telefoon die de pushmeldingen krijgt.
3. Klik op **Opslaan**.

De waardering 3 is normaal: de add-on krijgt netwerkrechten (*Host*) omdat nmap die nodig heeft.

### 5. Starten en controleren

1. Ga naar het tabblad **Info**, zet **Watchdog** aan en klik op **Starten**.
2. Open na een minuut het tabblad **Logboek**. Als het goed is, zie je:

```
Netwerkscanner start, tijdzone Europe/Amsterdam, subnetten: 192.168.1.0/24, 192.168.30.0/24
Ingelogd op UniFi via https://192.168.1.227/api/auth/login
Eerste inventaris: 61 apparaten vastgelegd zonder meldingen
Scan top van 192.168.1.222 klaar in 26 s
```

Bij de eerste start legt de scanner alle aanwezige apparaten vast als beginsituatie, zonder
meldingen. Daarna scant hij ze een voor een op de achtergrond.

## Bijwerken

Na een nieuwe versie op `main` toont Home Assistant bij de add-on een knop **Bijwerken**.
Zie je die niet? Ga dan naar **Instellingen → Apps → App installeren → ⋮ → Controleren op updates**.

## Problemen oplossen

| Melding | Oorzaak | Oplossing |
| --- | --- | --- |
| `GitHub returned 404 for https://api.github.com/repos/...` | Repository is privé, of toegevoegd in HACS | Zet de repository op openbaar en voeg hem toe via **Instellingen → Apps** (stap 3) |
| `The repository does not seem to be a integration, but an add-on repository` | Toegevoegd in HACS | Verwijder hem uit HACS en gebruik stap 3 |
| `Inloggen op UniFi mislukt` | Verkeerde gebruikersnaam of wachtwoord | Controleer stap 1 en de configuratie |
| `401 Client Error: Unauthorized for url: http://supervisor/core/api/...` | Add-on krijgt geen toegang tot HA | Werk bij naar versie 0.1.2 of nieuwer |
| Geen poorten bij apparaten in `192.168.30.x` | Firewall blokkeert verkeer naar het IoT-netwerk | Sta in UniFi verkeer toe van `192.168.1.253` naar `192.168.30.0/24` |

## Ontwikkelen

```
pip install pytest requests
python -m pytest
```
