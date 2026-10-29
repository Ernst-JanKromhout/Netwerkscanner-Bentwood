# Wat is er nieuw

## 0.1.12

- Geen waarschuwing meer over sensoren groter dan 16 KB. De apparatenlijst staat nu verdeeld over drie sensoren (*apparaten deel 1 t/m 3*), met alleen wat het dashboard toont, en elke lijst blijft onder de grens.
- De poortenlijst noemt per poort één apparaat of hoeveel het er zijn, in plaats van alle namen.
- Het dashboard schakelt vanzelf over op de nieuwe sensoren.

## 0.1.11

- Sensoren gaan via MQTT, als de Mosquitto-app draait. Ze staan nu onder één apparaat **Netwerkscanner**, overleven een herstart van Home Assistant en zijn te hernoemen of aan een ruimte te koppelen. De entity_id's blijven hetzelfde, dus je dashboard blijft werken. Zonder Mosquitto gaat het zoals voorheen.
- IPS-meldingen werken weer op nieuwere UniFi Network-versies: de scanner leest ze uit het systeemlog van de nieuwe API. Lukt uitlezen niet, dan staat in het logboek per manier waarom.

## 0.1.10

- Knop **Nu scannen** op het dashboard: kies een apparaat en start meteen een poortscan. De uitslag komt als melding in HA, met kleur en uitleg per poort.
- Het dashboard krijgt bij een update automatisch de nieuwe indeling, zolang je het niet zelf hebt aangepast. Verwijderen en opnieuw aanmaken is niet meer nodig.

## 0.1.9

- Bewaking op aanvallen: de scanner leest elke 5 minuten de IPS-meldingen van je UniFi-gateway uit.
- Mislukte inlogpogingen op Home Assistant worden opgemerkt.
- Beide geven een pushmelding (mislukte logins hooguit één keer per uur per IP) en staan in het dagrapport.
- Op het dashboard: een rode tegel *Aanvallen vandaag* en een blok *Beveiliging* met de laatste meldingen.

## 0.1.8

- Elke open poort krijgt een kleur naar risico: 🔴 hoog, 🟠 let op, 🟢 normaal. De gevaarlijkste staan bovenaan.
- De melding bij een nieuwe open poort toont dezelfde kleur.
- Dit overzicht van wijzigingen staat voortaan bij elke update.

## 0.1.7

- Uitleg per open poort op het dashboard en in de melding bij een nieuwe poort.
- Apparaten in drie kolommen naast elkaar, op de telefoon onder elkaar.
- Naam geven staat op het overzicht zelf, het tabblad Namen is weg.
- De naam uit UniFi wordt niet meer overschreven door DNS, dus geen heen-en-weer-wijzigingen in het dagrapport.
- Een half antwoord van UniFi geeft een waarschuwing in plaats van een foutmelding.

## 0.1.6

- Dashboard, keuzelijsten en scripts worden bij de start automatisch aangemaakt als ze ontbreken.
- Zelf een naam geven aan een apparaat, bijvoorbeeld als het op Onbekend staat.

## 0.1.5

- Dashboard heet Netwerk, standaardadres /dashboard-netwerk/overzicht.

## 0.1.4

- De pushmelding is alleen een seintje dat het dashboard opent, zonder knoppen.

## 0.1.3

- Sensoren voor het dashboard, goedkeuren en afkeuren van apparaten, namen uit UniFi.

## 0.1.2

- Token van Home Assistant uit de s6-omgeving gelezen.

## 0.1.1

- Tijdzone van Home Assistant overgenomen.

## 0.1.0

- Eerste versie: inventaris via UniFi en nmap, poortscans, pushmelding en dagrapport om 07:30.
