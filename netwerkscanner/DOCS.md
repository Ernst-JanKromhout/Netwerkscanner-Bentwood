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
| Nieuwe open poort op niet-vertrouwd apparaat | Ja | Ja |
| Al het andere | Nee | Ja |

Het dagrapport komt op `report_time` als melding in Home Assistant, en met `report_to_notify`
ook als korte samenvatting op je telefoon.

Sensoren:

| Sensor | Waarde | Extra |
| --- | --- | --- |
| `sensor.netwerkscanner_apparaten_online` | apparaten online | `bekend_totaal` |
| `sensor.netwerkscanner_gebeurtenissen_vandaag` | wijzigingen vandaag | |
| `sensor.netwerkscanner_apparaten` | bekende apparaten | `apparaten`: naam, IP, MAC, online, vertrouwd, open poorten |
| `sensor.netwerkscanner_laatste_wijzigingen` | tijd van de laatste wijziging | `wijzigingen`: de laatste 25, nieuwste eerst |

Ook `sensor.netwerkscanner_te_beoordelen`: het aantal apparaten dat nog niet is goed- of afgekeurd.

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

## Instellen

1. Maak in UniFi een lokaal account met alleen leesrechten en vul `unifi_username` en `unifi_password` in.
2. Zet het IP van Home Assistant op de uitzonderingslijst van IDS/IPS op de gateway,
   anders blokkeert die de scans.
3. Sta in de UniFi-firewall verkeer toe van Home Assistant naar het IoT-subnet.
4. Zet apparaten die je vertrouwt in `trusted_macs`: daarvan krijg je nieuwe poorten alleen in het dagrapport.

`notify_services` accepteert elke dienst die `title` en `message` kent, bijvoorbeeld
`notify.mobile_app_<telefoon>` of `telegram_bot.send_message`.

`dashboard_path` is de pagina die opent als je op een pushmelding tikt, standaard `/dashboard-netwerk/overzicht`.
Pas hem aan als je dashboard een ander adres heeft.
