using System.Net;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Collections.Concurrent;
using Server.Modelli;
using Json.Schema;
using System.Globalization;
using System.Linq;

//gestisce le sessioni attive e conserva una chiave diversa per ogni client
ConcurrentDictionary<string, Sessione> sessioni = new ConcurrentDictionary<string, Sessione>();

//evita che due richieste scrivano contemporaneamente sul file delle misurazioni
SemaphoreSlim bloccoFile = new SemaphoreSlim(1, 1);

//calcola i percorsi degli schemi e del file che contiene le misurazioni
string cartellaPrincipale = Path.GetFullPath(
    Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."));

string percorsoSchema = Path.Combine(
    cartellaPrincipale, "schemas", "telemetry.json");

string cartellaDati = Path.Combine(cartellaPrincipale, "data");

Directory.CreateDirectory(cartellaDati);

string percorsoDati = Path.Combine(cartellaDati, "readings.json");

//crea il server HTTP e lo mette in ascolto sulla porta 5000
HttpListener server = new HttpListener();
server.Prefixes.Add("http://localhost:5000/");
server.Start();

Console.WriteLine("================================");
Console.WriteLine("       FRIGOTRACK SERVER");
Console.WriteLine("================================");
Console.WriteLine("Server avviato sulla porta 5000.");
Console.WriteLine("In attesa di richieste...");
Console.WriteLine();

//accetta continuamente le richieste e le affida alla funzione di gestione
while (true)
{
    HttpListenerContext richiesta = await server.GetContextAsync();
    _ = GestisciRichiestaAsync(richiesta);
}

//controlla endpoint e metodo HTTP, poi esegue l'operazione richiesta
async Task GestisciRichiestaAsync(HttpListenerContext richiesta)
{
    HttpListenerRequest domanda = richiesta.Request;
    HttpListenerResponse risposta = richiesta.Response;

    string percorso = domanda.Url!.AbsolutePath;
    string metodo = domanda.HttpMethod;

    Console.WriteLine("Richiesta ricevuta: " + percorso);

    if (percorso == "/api/handshake" && metodo == "POST")
    {
        try
        {
            //lettura dei dati inviati dal client
            using StreamReader lettore = new StreamReader(domanda.InputStream);
            string contenuto = await lettore.ReadToEndAsync();

            var dati = JsonSerializer.Deserialize<RichiestaHandshake>(contenuto);

            //parametri pubblici fissi del gruppo RFC 3526 gruppo 14, condivisi con il client
            string primoEsadecimale =
                "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
                "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
                "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
                "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" +
                "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB" +
                "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
                "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
                "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

            BigInteger p = new BigInteger(
                Convert.FromHexString(primoEsadecimale),
                isUnsigned: true, isBigEndian: true);
            BigInteger g = 2;

            //verifica che il client abbia usato il gruppo previsto e una chiave pubblica valida
            if (dati == null || dati.P != p.ToString() || dati.G != g.ToString() ||
                !BigInteger.TryParse(dati.A, out BigInteger A) || A < 2 || A > p - 2)
            {
                await InviaRispostaAsync(risposta, 400,
                    new { codice = 400, messaggio = "Parametri Diffie-Hellman non validi." });
                return;
            }

            //genera il segreto privato del server, che non viene mai trasmesso
            byte[] numeroCasuale = RandomNumberGenerator.GetBytes(32);
            BigInteger b = new BigInteger(
                numeroCasuale, isUnsigned: true, isBigEndian: true);
            CryptographicOperations.ZeroMemory(numeroCasuale);

            //calcolo della chiave pubblica del server
            BigInteger B = BigInteger.ModPow(g, b, p);

            //calcolo del segreto condiviso
            BigInteger K = BigInteger.ModPow(A, b, p);

            //applica SHA-256 al segreto condiviso per ottenere una chiave AES da 32 byte
            byte[] segreto = K.ToByteArray(isUnsigned: true, isBigEndian: true);
            byte[] chiave = SHA256.HashData(segreto);
            CryptographicOperations.ZeroMemory(segreto);

            //creazione della sessione
            string idSessione = Guid.NewGuid().ToString("N");

            Sessione nuovaSessione = new Sessione();
            nuovaSessione.Chiave = chiave;

            sessioni[idSessione] = nuovaSessione;

            Console.WriteLine("Handshake completato.");
            Console.WriteLine("Sessione creata: " + idSessione);

            await InviaRispostaAsync(risposta, 200, new
            {
                session_id = idSessione,
                B = B.ToString()
            });
        }
        catch (Exception)
        {
            await InviaRispostaAsync(risposta, 400,
                new { codice = 400, messaggio = "Richiesta handshake non valida." });
        }
    }

    else if (percorso == "/api/telemetry" && metodo == "POST")
    {
        try
        {
            //lettura della busta cifrata
            using StreamReader lettore = new StreamReader(domanda.InputStream);
            string contenuto = await lettore.ReadToEndAsync();

            BustaCifrata? busta = JsonSerializer.Deserialize<BustaCifrata>(contenuto);

            if (busta == null)
            {
                await InviaRispostaAsync(risposta, 400,
                    new { codice = 400, messaggio = "Busta non valida." });
                return;
            }

            //controllo della sessione
            if (!sessioni.TryGetValue(busta.SessionId, out Sessione? sessione))
            {
                await InviaRispostaAsync(risposta, 401,
                    new { codice = 401, messaggio = "Sessione inesistente." });
                return;
            }

            //decifratura del messaggio
            string jsonDecifrato = Cifratura.Decifra(
                busta.Ciphertext, busta.Tag, sessione.Chiave);

            //lettura dello schema
            string testoSchema = await File.ReadAllTextAsync(percorsoSchema);

            JsonSchema schema = JsonSchema.FromText(testoSchema);

            //validazione del messaggio
            using JsonDocument documento = JsonDocument.Parse(jsonDecifrato);

            var risultato = schema.Evaluate(documento.RootElement);

            if (!risultato.IsValid)
            {
                await InviaRispostaCifrataAsync(risposta, 400,
                    busta.SessionId, sessione.Chiave,
                    new { codice = 400, messaggio = "Misurazione non valida." });

                return;
            }

            //conversione del messaggio in un oggetto
            Misurazione? misura =
                JsonSerializer.Deserialize<Misurazione>(jsonDecifrato);

            if (misura == null)
            {
                await InviaRispostaCifrataAsync(risposta, 400,
                    busta.SessionId, sessione.Chiave,
                    new { codice = 400, messaggio = "Misurazione non valida." });

                return;
            }

            //controlla se la temperatura rientra nell'intervallo previsto per la merce
            bool allarme = false;

            if (misura.CargoType == "pharma" &&
                (misura.Temperatura < 2 || misura.Temperatura > 8))
            {
                allarme = true;
            }
            else if (misura.CargoType == "food" &&
                     (misura.Temperatura < 0 || misura.Temperatura > 8))
            {
                allarme = true;
            }
            else if (misura.CargoType == "frozen" &&
                     misura.Temperatura > -18)
            {
                allarme = true;
            }

            //carica le misurazioni già salvate, aggiunge quella nuova e riscrive il file JSON
            await bloccoFile.WaitAsync();

            try
            {
                List<Misurazione> misurazioni = new List<Misurazione>();

                if (File.Exists(percorsoDati))
                {
                    string datiSalvati = await File.ReadAllTextAsync(percorsoDati);

                    if (!string.IsNullOrWhiteSpace(datiSalvati))
                    {
                        misurazioni =
                            JsonSerializer.Deserialize<List<Misurazione>>(datiSalvati)
                            ?? new List<Misurazione>();
                    }
                }

                misurazioni.Add(misura);

                string jsonSalvato = JsonSerializer.Serialize(
                    misurazioni,
                    new JsonSerializerOptions { WriteIndented = true });

                await File.WriteAllTextAsync(percorsoDati, jsonSalvato);
            }
            finally
            {
                bloccoFile.Release();
            }

            Console.WriteLine("Misurazione ricevuta: " + misura.SensorId);
            Console.WriteLine("Temperatura: " + misura.Temperatura + " °C");

            if (allarme)
            {
                Console.WriteLine("ATTENZIONE: TEMPERATURA FUORI DALL'INTERVALLO!");
            }

            //preparazione della conferma
            var conferma = new
            {
                stato = "ok",
                messaggio = "Misurazione ricevuta correttamente.",
                allarme = allarme
            };

            await InviaRispostaCifrataAsync(risposta, 200,
                busta.SessionId, sessione.Chiave, conferma);
        }
        catch (CryptographicException)
        {
            await InviaRispostaAsync(risposta, 400,
                new { codice = 400, messaggio = "Busta cifrata non valida." });
        }
        catch (Exception)
        {
            await InviaRispostaAsync(risposta, 400,
                new { codice = 400, messaggio = "Errore nella misurazione." });
        }
    }

    else if (percorso == "/api/readings" && metodo == "POST")
    {
        try
        {
            //lettura della busta cifrata
            using StreamReader lettore = new StreamReader(domanda.InputStream);
            string contenuto = await lettore.ReadToEndAsync();

            BustaCifrata? busta = JsonSerializer.Deserialize<BustaCifrata>(contenuto);

            if (busta == null)
            {
                await InviaRispostaAsync(risposta, 400,
                    new { codice = 400, messaggio = "Busta non valida." });
                return;
            }

            //controllo della sessione
            if (!sessioni.TryGetValue(busta.SessionId, out Sessione? sessione))
            {
                await InviaRispostaAsync(risposta, 401,
                    new { codice = 401, messaggio = "Sessione inesistente." });
                return;
            }

            //decifratura della richiesta
            string jsonDecifrato = Cifratura.Decifra(
                busta.Ciphertext, busta.Tag, sessione.Chiave);

            //lettura dello schema
            string testoSchema = await File.ReadAllTextAsync(
                Path.Combine(cartellaPrincipale, "schemas", "readings_request.json"));

            JsonSchema schema = JsonSchema.FromText(testoSchema);

            //validazione della richiesta
            using JsonDocument documento = JsonDocument.Parse(jsonDecifrato);

            var risultato = schema.Evaluate(documento.RootElement);

            if (!risultato.IsValid)
            {
                await InviaRispostaAsync(risposta, 400,
                    new { codice = 400, messaggio = "Richiesta non valida." });
                return;
            }

            //conversione della richiesta
            RichiestaLetture richiestaLetture =
                JsonSerializer.Deserialize<RichiestaLetture>(jsonDecifrato)!;

            //controllo delle date
            if (!DateTime.TryParse(richiestaLetture.Inizio, null,
                    DateTimeStyles.RoundtripKind, out DateTime inizio) ||
                !DateTime.TryParse(richiestaLetture.Fine, null,
                    DateTimeStyles.RoundtripKind, out DateTime fine) ||
                inizio > fine)
            {
                await InviaRispostaAsync(risposta, 400,
                    new { codice = 400, messaggio = "Intervallo temporale non valido." });
                return;
            }

            //legge dal file le misurazioni già registrate
            List<Misurazione> misurazioni = new List<Misurazione>();

            await bloccoFile.WaitAsync();

            try
            {
                if (File.Exists(percorsoDati))
                {
                    string datiSalvati = await File.ReadAllTextAsync(percorsoDati);

                    if (!string.IsNullOrWhiteSpace(datiSalvati))
                    {
                        misurazioni =
                            JsonSerializer.Deserialize<List<Misurazione>>(datiSalvati)
                            ?? new List<Misurazione>();
                    }
                }
            }
            finally
            {
                bloccoFile.Release();
            }

            //seleziona solo le misurazioni del sensore comprese nell'intervallo richiesto
            List<Misurazione> risultati = misurazioni
                .Where(m =>
                    m.SensorId == richiestaLetture.SensorId &&
                    DateTime.TryParse(m.Timestamp, null,
                        DateTimeStyles.RoundtripKind, out DateTime data) &&
                    data >= inizio && data <= fine)
                .ToList();

            //preparazione della risposta
            var rispostaLetture = new
            {
                sensor_id = richiestaLetture.SensorId,
                misurazioni = risultati
            };

            string jsonRisposta = JsonSerializer.Serialize(rispostaLetture);

            //validazione della risposta con JSON Schema
            string testoSchemaRisposta = await File.ReadAllTextAsync(
                Path.Combine(cartellaPrincipale, "schemas", "readings_response.json"));

            JsonSchema schemaRisposta = JsonSchema.FromText(testoSchemaRisposta);

            using JsonDocument documentoRisposta = JsonDocument.Parse(jsonRisposta);

            var verificaRisposta = schemaRisposta.Evaluate(documentoRisposta.RootElement);

            if (!verificaRisposta.IsValid)
            {
                await InviaRispostaAsync(risposta, 400,
                    new { codice = 400, messaggio = "Errore nella risposta." });
                return;
            }

            Console.WriteLine("Richiesta misurazioni: " + richiestaLetture.SensorId);
            Console.WriteLine("Misurazioni trovate: " + risultati.Count);

            //invio della risposta cifrata
            await InviaRispostaCifrataAsync(risposta, 200,
                busta.SessionId, sessione.Chiave, rispostaLetture);
        }
        catch (CryptographicException)
        {
            await InviaRispostaAsync(risposta, 400,
                new { codice = 400, messaggio = "Busta cifrata non valida." });
        }
        catch (Exception)
        {
            await InviaRispostaAsync(risposta, 400,
                new { codice = 400, messaggio = "Errore nella richiesta." });
        }
    }

    else if (percorso == "/api/close" && metodo == "POST")
    {
        try
        {
            //lettura della busta cifrata
            using StreamReader lettore = new StreamReader(domanda.InputStream);
            string contenuto = await lettore.ReadToEndAsync();

            BustaCifrata? busta = JsonSerializer.Deserialize<BustaCifrata>(contenuto);

            if (busta == null)
            {
                await InviaRispostaAsync(risposta, 400,
                    new { codice = 400, messaggio = "Busta non valida." });
                return;
            }

            //controllo della sessione
            if (!sessioni.TryGetValue(busta.SessionId, out Sessione? sessione))
            {
                await InviaRispostaAsync(risposta, 401,
                    new { codice = 401, messaggio = "Sessione inesistente." });
                return;
            }

            //decifratura della richiesta
            string jsonDecifrato = Cifratura.Decifra(
                busta.Ciphertext, busta.Tag, sessione.Chiave);

            using JsonDocument documento = JsonDocument.Parse(jsonDecifrato);

            //controllo del messaggio
            if (!documento.RootElement.TryGetProperty("azione", out JsonElement azione) ||
                azione.GetString() != "chiudi" ||
                documento.RootElement.EnumerateObject().Count() != 1)
            {
                await InviaRispostaAsync(risposta, 400,
                    new { codice = 400, messaggio = "Richiesta di chiusura non valida." });
                return;
            }

            Console.WriteLine("Chiusura sessione: " + busta.SessionId);

            //invio della conferma cifrata prima di cancellare la chiave
            await InviaRispostaCifrataAsync(risposta, 200,
                busta.SessionId, sessione.Chiave,
                new { stato = "ok", messaggio = "Sessione chiusa correttamente." });

            //cancellazione della sessione
            if (sessioni.TryRemove(busta.SessionId, out Sessione? sessioneEliminata))
            {
                CryptographicOperations.ZeroMemory(sessioneEliminata.Chiave);
            }

            Console.WriteLine("Sessione eliminata.");
        }
        catch (CryptographicException)
        {
            await InviaRispostaAsync(risposta, 400,
                new { codice = 400, messaggio = "Busta cifrata non valida." });
        }
        catch (Exception)
        {
            await InviaRispostaAsync(risposta, 400,
                new { codice = 400, messaggio = "Errore nella chiusura della sessione." });
        }
    }

    else
    {
        await InviaRispostaAsync(risposta, 404,
            new { codice = 404, messaggio = "Endpoint non trovato." });
    }
}

//converte il contenuto in JSON e lo invia con il codice HTTP indicato
async Task InviaRispostaAsync(HttpListenerResponse risposta, int codice, object contenuto)
{
    byte[] dati = JsonSerializer.SerializeToUtf8Bytes(contenuto);

    risposta.StatusCode = codice;
    risposta.ContentType = "application/json; charset=utf-8";
    risposta.ContentLength64 = dati.Length;

    await risposta.OutputStream.WriteAsync(dati);
    risposta.Close();
}


//cifra la risposta prima di inserirla nella busta da inviare al client
async Task InviaRispostaCifrataAsync(
    HttpListenerResponse risposta,
    int codice,
    string idSessione,
    byte[] chiave,
    object contenuto)
{
    string json = JsonSerializer.Serialize(contenuto);

    var risultato = Cifratura.Cifra(json, chiave);

    BustaCifrata busta = new BustaCifrata
    {
        SessionId = idSessione,
        Ciphertext = risultato.Cifrato,
        Tag = risultato.Tag
    };

    await InviaRispostaAsync(risposta, codice, busta);
}


//modello dei parametri ricevuti dal client durante l'handshake
class RichiestaHandshake
{
    public string P { get; set; } = "";
    public string G { get; set; } = "";
    public string A { get; set; } = "";
}
