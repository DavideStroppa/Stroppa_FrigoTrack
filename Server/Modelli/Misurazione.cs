
using System.Text.Json.Serialization;

namespace Server.Modelli
{
    public class Misurazione
    {
        //identificativo del sensore che ha inviato la misura
        [JsonPropertyName("sensor_id")]
        public string SensorId { get; set; } = "";

        //data e ora in cui è stata rilevata la misura
        [JsonPropertyName("timestamp")]
        public string Timestamp { get; set; } = "";

        //tipo di merce trasportata
        [JsonPropertyName("cargo_type")]
        public string CargoType { get; set; } = "";

        //temperatura rilevata in gradi Celsius
        [JsonPropertyName("temperature_c")]
        public double Temperatura { get; set; }

        //umidità rilevata dal sensore
        [JsonPropertyName("humidity")]
        public double Umidita { get; set; }

        //livello della batteria del sensore
        [JsonPropertyName("battery")]
        public int Batteria { get; set; }
    }
}
