# Netwerkscanner

Home Assistant-add-on die het thuisnetwerk volgt en meldt wat er verandert: nieuwe apparaten,
nieuwe of gesloten poorten, verdwenen apparaten. Je krijgt direct een pushmelding bij iets
urgents en elke ochtend een dagrapport.

Wat de add-on precies doet en welke opties er zijn, staat in [netwerkscanner/DOCS.md](netwerkscanner/DOCS.md).

## Installeren

Reken op een half uur. Je hebt nodig: Home Assistant OS op een 64-bit apparaat (bijvoorbeeld een
Raspberry Pi 4/5, ODROID of mini-pc), beheerrechten in Home Assistant, en als je UniFi hebt: beheerrechten
daar en het IP-adres van je UniFi-controller. UniFi is niet verplicht, zie [Zonder UniFi](#zonder-unifi).

### 1. UniFi-account met alleen leesrechten

1. Open UniFi via je controller (bijvoorbeeld `https://<ip-van-je-controller>`).
2. Ga naar **Admins & Users → Create New**.
3. Vink **Restrict to local access only** aan.
4. Kies bij **Network** de rol **View Only**.
5. Noteer de gebruikersnaam en het wachtwoord. Die vul je in stap 4 in.

### 2. Uitzondering in IDS/IPS

Een UniFi-gateway met IDS/IPS ziet poortscans anders als aanval en blokkeert ze.

1. Ga in UniFi Network naar **Settings → CyberSecure → Intrusion Prevention**.
2. Voeg het IP-adres van je Home Assistant toe aan de uitzonderingen.
   De precieze naam van die lijst verschilt per UniFi-versie.

### 3. Repository toevoegen in Home Assistant

De repository moet **openbaar** zijn. Een privé-repository kan Home Assistant niet ophalen.

1. Ga in Home Assistant naar **Instellingen → Apps** (in oudere versies: *Add-ons*).
2. Klik rechtsonder op **App installeren**.
3. Klik rechtsboven op **⋮ → Repositories**.
4. Plak `https://github.com/Ernst-JanKromhout/Netwerkscanner-Bentwood` en klik op **Toevoegen**, daarna op **Sluiten**.
5. Ververs de pagina (F5). Onderaan staat nu het blok *Netwerkscanner*.

Let op: voeg de repository **niet** toe in HACS. HACS is alleen voor integraties en kaarten,
niet voor add-ons.

### 4. Installeren en instellen

1. Klik op **Netwerkscanner** en daarna op **Installeren**. Je Home Assistant bouwt de add-on zelf.
   Dat duurt een paar minuten.
2. Open het tabblad **Configuratie** en vul in:
   - `unifi_host`: het IP-adres van je UniFi-controller
   - `unifi_username` en `unifi_password`: het account uit stap 1
   - `subnets`: de netwerken die gescand worden, bijvoorbeeld `192.168.1.0/24`
   - `notify_services`: waar pushmeldingen heen gaan, bijvoorbeeld `notify.mobile_app_<telefoon>`
3. Klik op **Opslaan**.

De waardering 3 is normaal: de add-on krijgt netwerkrechten (*Host*) omdat nmap die nodig heeft.

### 5. Starten en controleren

1. Ga naar het tabblad **Info**, zet **Watchdog** aan en klik op **Starten**.
2. Open na een minuut het tabblad **Logboek**. Als het goed is, zie je:

```
Netwerkscanner start, tijdzone Europe/Amsterdam, subnetten: <jouw subnetten>
Ingelogd op UniFi via https://<ip-van-je-controller>/api/auth/login
Eerste inventaris: <aantal> apparaten vastgelegd zonder meldingen
Scan top van <ip> klaar in <n> s
```

Bij de eerste start legt de scanner alle aanwezige apparaten vast als beginsituatie, zonder
meldingen. Daarna scant hij ze een voor een op de achtergrond.

### 6. Dashboard toevoegen

De add-on vult de sensoren zelf, maar het dashboard en de knoppen zet je eenmalig met de hand in
Home Assistant. De tekst om te plakken staat in de map [`dashboard/`](dashboard/).

1. **Keuzelijst.** Ga naar **Instellingen → Apparaten & diensten → Helpers → Helper aanmaken → Dropdown**.
   Naam: `Netwerkscanner te beoordelen`, één optie: `Niets te beoordelen`. Controleer dat de entiteit
   `input_select.netwerkscanner_te_beoordelen` heet. De add-on vult de lijst daarna zelf.
2. **Drie scripts.** Ga naar **Instellingen → Automatiseringen en scènes → Scripts → Script toevoegen →
   Nieuw script maken → ⋮ → Bewerken in YAML**. Plak het eerste blok uit
   [`dashboard/scripts.yaml`](dashboard/scripts.yaml) en sla op. Herhaal dat voor de andere twee.
   De entiteiten moeten `script.netwerkscanner_goedkeuren`, `script.netwerkscanner_afkeuren` en
   `script.netwerkscanner_alles_goedkeuren` heten. Klopt een naam niet, pas hem dan aan via het tandwiel van het script.
3. **Dashboard.** Ga naar **Instellingen → Dashboards → Dashboard toevoegen → Nieuw dashboard vanaf nul**
   en noem het `Netwerk`. Open het, klik op het potlood, dan **⋮ → Ruwe configuratie-editor**, vervang alles door
   de inhoud van [`dashboard/dashboard.yaml`](dashboard/dashboard.yaml) en sla op.

Tik je op een pushmelding, dan opent de HA-app `/dashboard-netwerk/overzicht`. Heeft je dashboard een ander
adres, pas dan de optie `dashboard_path` aan.

Eerste keer: alle apparaten staan op *te beoordelen*. Loop de lijst door, keur af wat je niet kent en
druk dan op **Alle openstaande goedkeuren**. Dat is je beginsituatie.

## Zonder UniFi

Laat `unifi_host`, `unifi_username` en `unifi_password` leeg. De scanner werkt dan alleen met nmap:
apparaten worden gevonden via de ping-sweep en namen komen uit DNS. Je ziet minder namen en fabrikanten.
Sla stap 1 en 2 dan over, maar zet een eventuele IDS/IPS van je eigen router wel op een uitzondering
voor het IP van Home Assistant.

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
| Geen poorten bij apparaten in een ander subnet (bijv. IoT) | Firewall blokkeert verkeer tussen de netwerken | Sta in UniFi verkeer toe van het IP van Home Assistant naar dat subnet |

## Ontwikkelen

```
pip install pytest requests
python -m pytest
```
