# Netwerkscanner

Volgt je thuisnetwerk en meldt wat er verandert: nieuwe apparaten, nieuwe of gesloten poorten,
gewijzigde diensten, verdwenen en teruggekeerde apparaten, en IP- of naamwissels.

## Hoe het werkt

- **UniFi-API** (elke minuut): de lijst met actieve clients van de controller.
- **Pingsweep** (elke 15 minuten): vangt apparaten die UniFi mist.
- **Poortscan**: direct bij een nieuw apparaat, elke nacht de top 1000 TCP-poorten,
  zondagnacht alle TCP-poorten plus de top 100 UDP-poorten.
- **Opslag**: SQLite in `/data/netwerkscanner.db`, gaat mee in de gewone HA-back-up.

De eerste keer legt de scanner alle aanwezige apparaten vast als beginsituatie, zonder meldingen.

## Meldingen

| Gebeurtenis | Pushmelding | Dagrapport |
| --- | --- | --- |
| Nieuw apparaat | Ja (niet voor `trusted_macs`) | Ja |
| Uitslag van de eerste poortscan van een nieuw apparaat | Ja (niet voor `trusted_macs`) | Ja |
| Nieuwe open poort op niet-vertrouwd apparaat | Ja | Ja |
| Afgekeurd apparaat weer online | Ja | Ja |
| Onbekend netwerk (één keer per netwerk) | Ja | Ja |
| Storing van de scanner zelf (langer dan 30 minuten) en herstel | Ja | Ja |
| Al het andere | Nee | Ja |

### Wat is dit apparaat?

De melding bij een nieuw apparaat zegt wie het maakte. De scanner zoekt de fabrikant op via de eerste drie
bytes van het MAC-adres, in de lijst die nmap meelevert (geen internet nodig). Je ziet dan:

- **Fabrikant: ...** als die bekend is. Die komt ook op het dashboard, ook bij apparaten die er al waren.
- **⚠️ Fabrikant verborgen** als de fabrikant zijn prefix anoniem registreerde (*Private*). Dat mag, maar het
  zegt je niets. Kijk dan extra goed naar de poorten en de hostnaam.
- **⚠️ Fabrikant onbekend** als het prefix in geen enkele lijst staat.
- **Hostnaam wijst op: ...** als de hostnaam een chip of bouwset verraadt, zoals `imx8mm-...` (NXP i.MX,
  embedded Linux) of `esp32-...` (ESP-chip).

Een willekeurig (privé) MAC-adres krijgt geen waarschuwing: dat is bijna altijd een telefoon of laptop.

Zodra de eerste poortscan klaar is, volgt een tweede melding met de open poorten, met kleur en uitleg en de
gevaarlijkste bovenaan. Reageert het apparaat niet, dan hoor je dat ook, en de echte uitslag volgt na de
nachtscan.

Het dagrapport komt op `report_time` als melding in Home Assistant, en met `report_to_notify`
ook als korte samenvatting op je telefoon.

Sensoren:

Draait de Mosquitto-app, dan maakt de scanner zijn sensoren via MQTT. Ze staan dan onder het apparaat
**Netwerkscanner**, blijven bestaan na een herstart van Home Assistant en zijn te hernoemen of aan een ruimte te
koppelen. Zonder Mosquitto zet de scanner ze via de REST-API; na een herstart van HA zijn ze er dan pas weer na
de volgende ronde (binnen 5 minuten).

| Sensor | Waarde | Extra |
| --- | --- | --- |
| `sensor.netwerkscanner_status` | `werkt` of `storing` | `bronnen`: per bron of hij werkt, wanneer laatst gelukt en de fout |
| `sensor.netwerkscanner_onbekende_netwerken` | onbekende netwerken (laatste 30 dagen) | `netwerken`: netwerk, waar gezien, sinds |
| `sensor.netwerkscanner_apparaten_online` | apparaten online | `bekend_totaal` |
| `sensor.netwerkscanner_apparaten` | bekende apparaten | |
| `sensor.netwerkscanner_apparaten_1` t/m `_3` | apparaten in dit deel | `apparaten`: naam, IP, status, online, open poorten |
| `sensor.netwerkscanner_poorten` | soorten open poorten | `poorten`: poort, uitleg, risico, op welk apparaat |
| `sensor.netwerkscanner_te_beoordelen` | apparaten die nog niet zijn goed- of afgekeurd | |
| `sensor.netwerkscanner_aanvallen_vandaag` | aanvallen en mislukte logins vandaag | `meldingen` |
| `sensor.netwerkscanner_gebeurtenissen_vandaag` | wijzigingen vandaag | |
| `sensor.netwerkscanner_laatste_wijzigingen` | tijd van de laatste wijziging | `wijzigingen`: de laatste 10, nieuwste eerst |

## Onbekende netwerken

De scanner kent je eigen netwerken: wat UniFi heeft (LAN, VLAN's zoals IoT, VPN's), de internetkant van je
gateway (zoals het netwerk van een modem ervoor) en wat je in `subnets` en `known_subnets` zet. Elke 5 minuten
kijkt hij of er een privé-IP opduikt dat daar niet in past: bij een apparaat van de afgelopen week, in een
IPS-melding of bij een mislukte login. Zo'n netwerk krijg je één keer als pushmelding, het staat in het dagrapport
en op het dashboard onder **Onbekende netwerken**.

Meestal is het een extra router of extender, een apparaat met een eigen hotspot, een VPN of een apparaat met een
verkeerd ingesteld vast IP. Hoort het erbij, zet het netwerk dan in `known_subnets`, bijvoorbeeld `192.168.4.0/24`.

## Als de scanner zelf een storing heeft

De scanner houdt bij of elke bron nog werkt: de UniFi-controller, de IPS-meldingen, de pingsweep en de koppeling
met Home Assistant (voor de knoppen en de login-bewaking). Faalt een bron langer dan 30 minuten, dan krijg je één
pushmelding, en één als hij weer werkt. Op het dashboard staat dan bovenaan welke bron niet werkt en waarom.
Een IPS-uitlezing die sinds de start nog nooit werkte geeft geen melding, omdat dat op sommige UniFi-versies
gewoon niet kan; je ziet het wel in `sensor.netwerkscanner_status`.

Lukt inloggen op UniFi niet, bijvoorbeeld na een wachtwoordwissel, dan wacht de scanner steeds langer
(1, 2, 5 en daarna 15 minuten) voor hij het opnieuw probeert, zodat UniFi je account niet blokkeert.

Kwam een pushmelding niet aan omdat Home Assistant even weg was, dan probeert de scanner hem elke minuut
opnieuw, tot een dag lang. Daarna staat hij alleen nog in het dagrapport.

## Goedkeuren en afkeuren

Een pushmelding is alleen een seintje: tik erop en de HA-app opent het dashboard op `dashboard_path`
(standaard `/dashboard-netwerk/overzicht`). Daar keur je het apparaat goed of af. Zo raak je niets kwijt als je
de melding per ongeluk wegtikt; de melding staat ook in Home Assistant zelf.

- **Goedkeuren**: het apparaat telt als vertrouwd. Nieuwe poorten op dat apparaat zie je alleen nog in het dagrapport.
- **Afkeuren**: het apparaat blijft gevolgd. Zolang het online is, staat het bovenaan het dagrapport.
  Afkeuren blokkeert het apparaat niet; dat doe je zelf in UniFi.

Het dashboard werkt met de keuzelijst `input_select.netwerkscanner_te_beoordelen`, die de add-on
vult met openstaande apparaten. Een script vuurt dan het event `netwerkscanner_review` af met
`action` (`approve`, `reject` of `approve_all`) en `device` (de gekozen optie):

```yaml
sequence:
  - event: netwerkscanner_review
    event_data:
      action: approve
      device: "{{ states('input_select.netwerkscanner_te_beoordelen') }}"
```

De add-on maakt de keuzelijst, de scripts en het dashboard bij de start zelf aan als ze ontbreken
(optie `create_dashboard`). Bestaande versies worden nooit overschreven.

## Zelf een naam geven

Kies op het dashboard onder **Naam geven** een apparaat, typ een naam en druk op **Naam opslaan**.
Die naam gaat voor alles: de naam uit UniFi, de hostnaam en de fabrikant. Hij blijft staan als het apparaat
later een ander IP of een andere hostnaam krijgt. Sla je een lege naam op, dan komt de oude naam terug.
In het dagrapport staat de wijziging onder *Zelf hernoemd*.

## Nu scannen

Kies onder **Apparaat** een apparaat en druk op **Nu scannen**. Na een halve minuut tot een paar minuten
krijg je in HA een melding met de open poorten, met kleur en uitleg.

## Wat betekenen de poorten

Onder **Wat betekenen de poorten** staat elke open poort die de scanner vond, met in één zin waar hij voor dient
en op welk apparaat hij openstaat. Dezelfde uitleg staat in de melding bij een nieuwe open poort.
Zie je een poort die je niet verwacht, zoals Telnet (23) of Extern bureaublad (3389), zet die dienst dan uit.

## Aanvallen en mislukte logins

De scanner leest elke 5 minuten de meldingen van IDS/IPS op je UniFi-gateway uit. Zet die in UniFi aan
(CyberSecure of Threat Management, het liefst op *Detect and block*), anders is er niets te lezen.
Op UniFi Network 8.x en later komen ze uit het systeemlog van de nieuwe API, op oudere versies uit de oude
endpoints. Staat er in het logboek *geen enkele manier om IPS-meldingen te lezen werkt*, dan staat erachter
waarom per manier, bijvoorbeeld omdat het UniFi-account geen leesrechten op het systeemlog heeft.
Daarnaast ziet de scanner het als iemand met een verkeerd wachtwoord probeert in te loggen op Home Assistant.
Je krijgt een pushmelding, het blok **Beveiliging** op het dashboard toont de laatste vijf, en het dagrapport
heeft ze bovenaan. 🛡️ betekent geblokkeerd, 🚨 dat de gateway het alleen zag of dat het een mislukte login was.

## Instellen

1. Maak in UniFi een lokaal account met alleen leesrechten en vul `unifi_username` en `unifi_password` in.
2. Zet het IP van Home Assistant op de uitzonderingslijst van IDS/IPS op de gateway,
   anders blokkeert die de scans.
3. Sta in de UniFi-firewall verkeer toe van Home Assistant naar het IoT-subnet.
4. Zet apparaten die je vertrouwt in `trusted_macs`: daarvan krijg je nieuwe poorten alleen in het dagrapport.

`notify_services` accepteert elke dienst die `title` en `message` kent, bijvoorbeeld
`notify.mobile_app_<telefoon>` of `telegram_bot.send_message`.

`unifi_fingerprint`: laat leeg. De scanner pint het certificaat van je controller bij de eerste verbinding vast
(op `/data/unifi_fingerprints.json`) en praat daarna alleen nog met die controller, ook als het certificaat
zelfondertekend is. Zo kan niemand op je netwerk zich voordoen als de Cloud Key en je UniFi-wachtwoord
onderscheppen. Krijgt de Cloud Key een nieuw certificaat, bijvoorbeeld na een update, dan meldt de scanner
een storing met de nieuwe vingerafdruk. Klopt dat, vul die waarde dan hier in.
Met `unifi_verify_ssl: true` controleert de scanner het certificaat op de gewone manier en pint hij niet.

`scan_workers` (1 tot 4, standaard 2): hoeveel poortscans tegelijk lopen. Een nieuw apparaat en **Nu scannen**
gaan altijd voor op de nachtelijke scans.

`dashboard_path` is de pagina die opent als je op een pushmelding tikt, standaard `/dashboard-netwerk/overzicht`.
Pas hem aan als je dashboard een ander adres heeft.
