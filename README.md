# FrigoTrack – Telemetria Sicura

## Descrizione
FrigoTrack è un progetto client-server HTTP che simula il monitoraggio della temperatura e dell'umidità durante il trasporto di alimenti e farmaci.

L'obiettivo è permettere ai sensori di inviare dati a un server in modo sicuro, utilizzando la cifratura e la validazione dei messaggi JSON.

## Funzionalità
- Comunicazione tra client e server tramite HTTP.
- Scambio delle chiavi con l'algoritmo Diffie-Hellman.
- Cifratura dei dati inviati dai sensori.
- Validazione dei messaggi tramite JSON Schema.
- Simulazione di almeno 3 sensori.
- Salvataggio e consultazione delle misurazioni.
- Segnalazione delle temperature fuori dai limiti consentiti.

## Funzionamento
1. Il client si collega al server ed esegue lo scambio delle chiavi.
2. Client e server calcolano una chiave segreta condivisa.
3. Il sensore genera una misurazione in formato JSON.
4. Il client valida e cifra il messaggio prima di inviarlo.
5. Il server decifra e controlla i dati ricevuti.
6. Se la temperatura è fuori dai limiti, viene generato un allarme.

## Endpoint HTTP

| Endpoint | Metodo | Descrizione |
|---|---|---|
| `/api/handshake` | POST | Scambio delle chiavi |
| `/api/telemetry` | POST | Invio delle misurazioni |
| `/api/readings` | POST | Consultazione delle misurazioni |
| `/api/close` | POST | Chiusura della sessione |

## Sicurezza
Il progetto utilizza Diffie-Hellman per concordare una chiave senza trasmetterla direttamente sulla rete.

I messaggi vengono cifrati e controllati tramite JSON Schema per verificare che rispettino il formato richiesto.

## Obiettivo
Realizzare un sistema semplice per comprendere il funzionamento della comunicazione client-server, della crittografia e della validazione dei dati JSON.

## Autore
Progetto scolastico individuale – Classe 5IB

Materia: Tecnologie e Progettazione di Sistemi Informatici e di Telecomunicazioni (TPSIT).
