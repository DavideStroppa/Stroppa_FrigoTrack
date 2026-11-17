using System.Net;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Xunit;

namespace Tests
{
    public class TestFrigoTrack
    {
        //indirizzo usato dai test per contattare il server avviato
        string indirizzoServer = "http://localhost:5000/";

        //crea una sessione e restituisce la chiave condivisa
        private async Task<(string Id, byte[] Chiave)> CreaSessione()
        {
            //parametri fissi del gruppo RFC 3526 gruppo 14 (2048 bit)
            string primoEsadecimale =
                "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
                "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
                "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
                "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" +
                "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB" +
                "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
                "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
                "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

            //converte il numero primo RFC 3526 da esadecimale a BigInteger
            BigInteger p = new BigInteger(
                Convert.FromHexString(primoEsadecimale),
                isUnsigned: true, isBigEndian: true);
            BigInteger g = 2;
            BigInteger a = 123456789;

            //calcola la chiave pubblica del client
            BigInteger A = BigInteger.ModPow(g, a, p);

            //crea il collegamento HTTP con il server
            using HttpClient client = new HttpClient();

            var richiesta = new
            {
                P = p.ToString(),
                G = g.ToString(),
                A = A.ToString()
            };

            string json = JsonSerializer.Serialize(richiesta);

            StringContent contenuto = new StringContent(
                json, Encoding.UTF8, "application/json");

            HttpResponseMessage risposta = await client.PostAsync(
                indirizzoServer + "api/handshake", contenuto);

            Assert.Equal(HttpStatusCode.OK, risposta.StatusCode);

            string risultato = await risposta.Content.ReadAsStringAsync();

            using JsonDocument documento = JsonDocument.Parse(risultato);

            string id = documento.RootElement
                .GetProperty("session_id").GetString()!;

            BigInteger B = BigInteger.Parse(
                documento.RootElement.GetProperty("B").GetString()!);

            //calcola il segreto condiviso usando la chiave pubblica del server
            BigInteger K = BigInteger.ModPow(B, a, p);

            byte[] segreto = K.ToByteArray(
                isUnsigned: true, isBigEndian: true);

            //ricava una chiave AES di 32 byte dal segreto condiviso
            byte[] chiave = SHA256.HashData(segreto);

            return (id, chiave);
        }

        //crea una busta cifrata
        private string CreaBusta(string id, byte[] chiave, string messaggio)
        {
            //genera un nonce casuale per AES-GCM
            byte[] nonce = RandomNumberGenerator.GetBytes(12);

            byte[] dati = Encoding.UTF8.GetBytes(messaggio);
            byte[] datiCifrati = new byte[dati.Length];
            byte[] tag = new byte[16];

            //cifra il messaggio e genera il tag di autenticazione
            using (AesGcm aes = new AesGcm(chiave, 16))
            {
                aes.Encrypt(nonce, dati, datiCifrati, tag);
            }

            //inserisce il nonce prima dei dati cifrati
            byte[] busta = new byte[nonce.Length + datiCifrati.Length];

            Buffer.BlockCopy(nonce, 0, busta, 0, nonce.Length);
            Buffer.BlockCopy(datiCifrati, 0, busta, nonce.Length, datiCifrati.Length);

            //prepara la busta nel formato richiesto dal server
            var risultato = new
            {
                session_id = id,
                ciphertext = Convert.ToBase64String(busta),
                tag = Convert.ToBase64String(tag)
            };

            return JsonSerializer.Serialize(risultato);
        }

        //test 1: handshake riuscito
        [Fact]
        public async Task HandshakeRiuscito()
        {
            //crea una sessione valida prima di inviare il messaggio
            var sessione = await CreaSessione();

            Assert.False(string.IsNullOrEmpty(sessione.Id));
            Assert.Equal(32, sessione.Chiave.Length);
        }

        //test 2: invio di una misurazione valida
        [Fact]
        public async Task MessaggioValido()
        {
            var sessione = await CreaSessione();

            //crea una misurazione con valori corretti
            string json = JsonSerializer.Serialize(new
            {
                sensor_id = "CELLA-BG-001",
                timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                cargo_type = "pharma",
                temperature_c = 4.5,
                humidity = 55,
                battery = 90
            });

            string busta = CreaBusta(
                sessione.Id, sessione.Chiave, json);

            using HttpClient client = new HttpClient();

            HttpResponseMessage risposta = await client.PostAsync(
                indirizzoServer + "api/telemetry",
                new StringContent(busta, Encoding.UTF8, "application/json"));

            Assert.Equal(HttpStatusCode.OK, risposta.StatusCode);
        }

        //test 3: invio di una misurazione non valida
        [Fact]
        public async Task MessaggioNonValido()
        {
            var sessione = await CreaSessione();

            string json = JsonSerializer.Serialize(new
            {
                sensor_id = "CELLA-BG-001",
                timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                cargo_type = "pharma",
                temperature_c = 100,
                humidity = 55,
                battery = 90
            });

            string busta = CreaBusta(
                sessione.Id, sessione.Chiave, json);

            using HttpClient client = new HttpClient();

            HttpResponseMessage risposta = await client.PostAsync(
                indirizzoServer + "api/telemetry",
                new StringContent(busta, Encoding.UTF8, "application/json"));

            Assert.Equal(HttpStatusCode.BadRequest, risposta.StatusCode);
        }

        //test 4: busta cifrata manomessa
        [Fact]
        public async Task BustaManomessa()
        {
            var sessione = await CreaSessione();

            //crea un messaggio da cifrare prima di alterarne il tag
            string json = "{\"azione\":\"test\"}";

            string busta = CreaBusta(
                sessione.Id, sessione.Chiave, json);

            using JsonDocument documento = JsonDocument.Parse(busta);

            string ciphertext = documento.RootElement
                .GetProperty("ciphertext").GetString()!;

            //sostituisce il tag corretto con un tag falso
            string tag = Convert.ToBase64String(new byte[16]);

            var bustaModificata = new
            {
                session_id = sessione.Id,
                ciphertext = ciphertext,
                tag = tag
            };

            using HttpClient client = new HttpClient();

            HttpResponseMessage risposta = await client.PostAsync(
                indirizzoServer + "api/telemetry",
                new StringContent(
                    JsonSerializer.Serialize(bustaModificata),
                    Encoding.UTF8, "application/json"));

            Assert.Equal(HttpStatusCode.BadRequest, risposta.StatusCode);
        }

        //test 5: sessione inesistente
        [Fact]
        public async Task SessioneInesistente()
        {
            //usa un identificativo che non esiste tra le sessioni del server
            var busta = new
            {
                session_id = "sessione-inesistente",
                ciphertext = Convert.ToBase64String(new byte[20]),
                tag = Convert.ToBase64String(new byte[16])
            };

            using HttpClient client = new HttpClient();

            HttpResponseMessage risposta = await client.PostAsync(
                indirizzoServer + "api/telemetry",
                new StringContent(
                    JsonSerializer.Serialize(busta),
                    Encoding.UTF8, "application/json"));

            Assert.Equal(HttpStatusCode.Unauthorized, risposta.StatusCode);
        }
    }
}
