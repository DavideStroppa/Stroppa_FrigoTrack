
using System.Net;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Json.Schema;
using Client.Sensori;

//indirizzo del server a cui il client invia le richieste
string indirizzoServer = "http://localhost:5000/";

//parametri fissi del gruppo RFC 3526 gruppo 14, usati da entrambi i programmi
string primoEsadecimale =
                "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
                "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
                "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
                "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" +
                "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB" +
                "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
                "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
                "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

BigInteger p = new BigInteger(Convert.FromHexString(primoEsadecimale), isUnsigned: true, isBigEndian: true);
BigInteger g = 2;

//genera il segreto privato casuale del client, che non viene inviato in rete
byte[] numeroCasuale = RandomNumberGenerator.GetBytes(32);
BigInteger a = new BigInteger(numeroCasuale, isUnsigned: true, isBigEndian: true);
CryptographicOperations.ZeroMemory(numeroCasuale);

//calcola la chiave pubblica A da inviare al server
BigInteger A = BigInteger.ModPow(g, a, p);

Console.WriteLine("==============================");
Console.WriteLine("       FRIGOTRACK CLIENT");
Console.WriteLine("==============================");

using HttpClient client = new HttpClient();

try
{
    //invia al server i parametri del gruppo e la chiave pubblica A
    var richiesta = new
    {
        P = p.ToString(),
        G = g.ToString(),
        A = A.ToString()
    };

    string jsonHandshake = JsonSerializer.Serialize(richiesta);

    StringContent contenutoHandshake = new StringContent(
        jsonHandshake, Encoding.UTF8, "application/json");

    HttpResponseMessage rispostaHandshake = await client.PostAsync(
        indirizzoServer + "api/handshake", contenutoHandshake);

    if (!rispostaHandshake.IsSuccessStatusCode)
    {
        Console.WriteLine("Errore durante l'handshake.");
        return;
    }

    string risultatoHandshake =
        await rispostaHandshake.Content.ReadAsStringAsync();

    var datiHandshake =
        JsonSerializer.Deserialize<RispostaHandshake>(risultatoHandshake);

    if (datiHandshake == null)
    {
        Console.WriteLine("Risposta del server non valida.");
        return;
    }

    //calcola il segreto condiviso usando la chiave pubblica B ricevuta dal server
    BigInteger B = BigInteger.Parse(datiHandshake.B);
    BigInteger K = BigInteger.ModPow(B, a, p);

    byte[] segreto = K.ToByteArray(isUnsigned: true, isBigEndian: true);
    byte[] chiave = SHA256.HashData(segreto);
    CryptographicOperations.ZeroMemory(segreto);

    Console.WriteLine("Handshake completato");
    Console.WriteLine("Sessione: " + datiHandshake.SessionId);

    //individua e carica lo schema usato per controllare le misurazioni
    string cartellaPrincipale = Path.GetFullPath(
        Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."));

    string percorsoSchema = Path.Combine(
        cartellaPrincipale, "schemas", "telemetry.json");

    string testoSchema = await File.ReadAllTextAsync(percorsoSchema);
    JsonSchema schema = JsonSchema.FromText(testoSchema);

    //simula tre sensori con identificativi e tipi di merce diversi
    List<Sensore> sensori = new List<Sensore>
    {
        new Sensore("CELLA-BG-001", "pharma"),
        new Sensore("CELLA-BG-002", "food"),
        new Sensore("CELLA-BG-003", "frozen")
    };

    bool sessioneAttiva = true;

    //mostra le operazioni disponibili finché la sessione rimane attiva
    while (sessioneAttiva)
    {
        Console.WriteLine();
        Console.WriteLine("========== MENU ==========");
        Console.WriteLine("1. Avvia i sensori");
        Console.WriteLine("2. Consulta le misurazioni");
        Console.WriteLine("3. Chiudi la sessione");
        Console.WriteLine("==========================");
        Console.Write("Scelta: ");

        string scelta = Console.ReadLine() ?? "";

        if (scelta == "1")
        {
            Console.WriteLine();
            Console.WriteLine("Sensori avviati.");
            Console.WriteLine("Premi INVIO per interrompere l'invio.");

            //attende INVIO in parallelo all'invio periodico delle misurazioni
            Task attesaFine = Task.Run(() => Console.ReadLine());

            while (!attesaFine.IsCompleted)
            {
                foreach (Sensore sensore in sensori)
                {
                    if (attesaFine.IsCompleted)
                    {
                        break;
                    }

                    //chiede al sensore di generare una nuova misurazione
                    MisurazioneClient misura = sensore.GeneraMisurazione();

                    string jsonMisura = JsonSerializer.Serialize(misura);

                    //controlla che il JSON rispetti lo schema prima di cifrarlo
                    using JsonDocument documento = JsonDocument.Parse(jsonMisura);

                    var risultato = schema.Evaluate(documento.RootElement);

                    if (!risultato.IsValid)
                    {
                        Console.WriteLine("Misurazione non valida.");
                        continue;
                    }

                    //cifra il JSON e prepara la busta da inviare al server
                    var datiCifrati = Cifratura.Cifra(jsonMisura, chiave);

                    BustaClient busta = new BustaClient
                    {
                        SessionId = datiHandshake.SessionId,
                        Ciphertext = datiCifrati.Cifrato,
                        Tag = datiCifrati.Tag
                    };

                    string jsonBusta = JsonSerializer.Serialize(busta);

                    StringContent contenuto = new StringContent(
                        jsonBusta, Encoding.UTF8, "application/json");

                    //invia la busta cifrata all'endpoint telemetry
                    HttpResponseMessage risposta = await client.PostAsync(
                        indirizzoServer + "api/telemetry", contenuto);

                    string testoRisposta =
                        await risposta.Content.ReadAsStringAsync();

                    if (risposta.StatusCode == HttpStatusCode.OK)
                    {
                        BustaClient? rispostaCifrata =
                            JsonSerializer.Deserialize<BustaClient>(testoRisposta);

                        if (rispostaCifrata != null)
                        {
                            string conferma = Cifratura.Decifra(
                                rispostaCifrata.Ciphertext,
                                rispostaCifrata.Tag,
                                chiave);

                            Console.WriteLine(misura.SensorId +
                                " - " + misura.Temperatura + " °C");

                            Console.WriteLine("Server: " + conferma);
                        }
                    }
                    else
                    {
                        Console.WriteLine("Errore HTTP: " +
                            (int)risposta.StatusCode);
                    }
                }

                //aspetta cinque secondi prima di generare un nuovo ciclo di misurazioni
                if (!attesaFine.IsCompleted)
                {
                    await Task.Delay(5000);
                }
            }

            Console.WriteLine("Invio dei sensori interrotto.");
        }
        else if (scelta == "2")
        {
            //mostra i sensori disponibili e chiede quale consultare
            Console.WriteLine();
            Console.WriteLine("Sensori disponibili:");

            foreach (Sensore sensore in sensori)
            {
                Console.WriteLine(sensore.Id);
            }

            Console.Write("Inserisci l'identificativo: ");
            string idSensore = Console.ReadLine() ?? "";

            if (!sensori.Any(s => s.Id == idSensore))
            {
                Console.WriteLine("Sensore inesistente.");
                continue;
            }

            //prepara una richiesta relativa alle ultime 24 ore
            var richiestaLetture = new RichiestaLettureClient
            {
                SensorId = idSensore,
                Inizio = DateTime.UtcNow.AddDays(-1).ToString("yyyy-MM-ddTHH:mm:ssZ"),
                Fine = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
            };

            string jsonRichiesta = JsonSerializer.Serialize(richiestaLetture);

            //controlla la richiesta prima di cifrarla e inviarla
            string percorsoRichiesta = Path.Combine(
                cartellaPrincipale, "schemas", "readings_request.json");

            string testoSchemaRichiesta =
                await File.ReadAllTextAsync(percorsoRichiesta);

            JsonSchema schemaRichiesta =
                JsonSchema.FromText(testoSchemaRichiesta);

            using JsonDocument documentoRichiesta =
                JsonDocument.Parse(jsonRichiesta);

            var verificaRichiesta =
                schemaRichiesta.Evaluate(documentoRichiesta.RootElement);

            if (!verificaRichiesta.IsValid)
            {
                Console.WriteLine("Richiesta non valida.");
                continue;
            }

            //cifratura della richiesta
            var datiCifrati = Cifratura.Cifra(jsonRichiesta, chiave);

            BustaClient busta = new BustaClient
            {
                SessionId = datiHandshake.SessionId,
                Ciphertext = datiCifrati.Cifrato,
                Tag = datiCifrati.Tag
            };

            StringContent contenuto = new StringContent(
                JsonSerializer.Serialize(busta),
                Encoding.UTF8, "application/json");

            //invia la richiesta cifrata all'endpoint readings
            HttpResponseMessage risposta = await client.PostAsync(
                indirizzoServer + "api/readings", contenuto);

            string testoRisposta =
                await risposta.Content.ReadAsStringAsync();

            if (risposta.StatusCode == HttpStatusCode.OK)
            {
                //decifra la risposta ricevuta dal server
                BustaClient? rispostaCifrata =
                    JsonSerializer.Deserialize<BustaClient>(testoRisposta);

                if (rispostaCifrata != null)
                {
                    string jsonRisposta = Cifratura.Decifra(
                        rispostaCifrata.Ciphertext,
                        rispostaCifrata.Tag,
                        chiave);

                    //verifica che anche la risposta rispetti il suo JSON Schema
                    string percorsoRisposta = Path.Combine(
                        cartellaPrincipale, "schemas", "readings_response.json");

                    string testoSchemaRisposta =
                        await File.ReadAllTextAsync(percorsoRisposta);

                    JsonSchema schemaRisposta =
                        JsonSchema.FromText(testoSchemaRisposta);

                    using JsonDocument documentoRisposta =
                        JsonDocument.Parse(jsonRisposta);

                    var verificaRisposta =
                        schemaRisposta.Evaluate(documentoRisposta.RootElement);

                    if (verificaRisposta.IsValid)
                    {
                        Console.WriteLine();
                        Console.WriteLine("Misurazioni ricevute:");
                        Console.WriteLine(jsonRisposta);
                    }
                    else
                    {
                        Console.WriteLine("Risposta del server non valida.");
                    }
                }
            }
            else
            {
                Console.WriteLine("Errore HTTP: " + (int)risposta.StatusCode);
                Console.WriteLine(testoRisposta);
            }
        }
        else if (scelta == "3")
        {
            //prepara il messaggio che chiede al server di chiudere la sessione
            string jsonChiusura = JsonSerializer.Serialize(
                new { azione = "chiudi" });

            //cifratura della richiesta
            var datiCifrati = Cifratura.Cifra(jsonChiusura, chiave);

            BustaClient busta = new BustaClient
            {
                SessionId = datiHandshake.SessionId,
                Ciphertext = datiCifrati.Cifrato,
                Tag = datiCifrati.Tag
            };

            StringContent contenuto = new StringContent(
                JsonSerializer.Serialize(busta),
                Encoding.UTF8, "application/json");

            //invia la richiesta cifrata all'endpoint close
            HttpResponseMessage risposta = await client.PostAsync(
                indirizzoServer + "api/close", contenuto);

            string testoRisposta =
                await risposta.Content.ReadAsStringAsync();

            if (risposta.StatusCode == HttpStatusCode.OK)
            {
                BustaClient? rispostaCifrata =
                    JsonSerializer.Deserialize<BustaClient>(testoRisposta);

                if (rispostaCifrata != null)
                {
                    string conferma = Cifratura.Decifra(
                        rispostaCifrata.Ciphertext,
                        rispostaCifrata.Tag,
                        chiave);

                    Console.WriteLine(conferma);
                }

                sessioneAttiva = false;
                Console.WriteLine("Sessione terminata.");
            }
            else
            {
                Console.WriteLine("Errore durante la chiusura.");
            }
        }
        else
        {
            Console.WriteLine("Scelta non valida.");
        }
    }
}
catch (HttpRequestException)
{
    Console.WriteLine("Impossibile collegarsi al server.");
}
catch (Exception errore)
{
    Console.WriteLine("ERRORE NEL PROGRAMMA:");
    Console.WriteLine(errore.ToString());

    Console.WriteLine();
    Console.WriteLine("Premi INVIO per chiudere...");
    Console.ReadLine();
}

//modello della risposta inviata dal server durante l'handshake
class RispostaHandshake
{
    [JsonPropertyName("session_id")]
    public string SessionId { get; set; } = "";

    [JsonPropertyName("B")]
    public string B { get; set; } = "";
}

//modello della busta cifrata scambiata con il server
class BustaClient
{
    [JsonPropertyName("session_id")]
    public string SessionId { get; set; } = "";

    [JsonPropertyName("ciphertext")]
    public string Ciphertext { get; set; } = "";

    [JsonPropertyName("tag")]
    public string Tag { get; set; } = "";
}
