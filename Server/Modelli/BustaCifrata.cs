using System.Text.Json.Serialization;

namespace Server.Modelli
{
    public class BustaCifrata
    {
        //identificativo della sessione usata per cifrare il messaggio
        [JsonPropertyName("session_id")]
        public string SessionId { get; set; } = "";

        //dati cifrati, codificati in Base64
        [JsonPropertyName("ciphertext")]
        public string Ciphertext { get; set; } = "";

        //tag usato da AES-GCM per verificare che il messaggio non sia stato modificato
        [JsonPropertyName("tag")]
        public string Tag { get; set; } = "";
    }
}
