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

De attributen van de laatste twee zijn bedoeld voor een dashboard, bijvoorbeeld met een Markdown-kaart.

## Instellen

1. Maak in UniFi een lokaal account met alleen leesrechten en vul `unifi_username` en `unifi_password` in.
2. Zet het IP van Home Assistant op de uitzonderingslijst van IDS/IPS op de gateway,
   anders blokkeert die de scans.
3. Sta in de UniFi-firewall verkeer toe van Home Assistant naar het IoT-subnet.
4. Zet apparaten die je vertrouwt in `trusted_macs`: daarvan krijg je nieuwe poorten alleen in het dagrapport.

`notify_services` accepteert elke dienst die `title` en `message` kent, bijvoorbeeld
`notify.mobile_app_<telefoon>` of `telegram_bot.send_message`.
