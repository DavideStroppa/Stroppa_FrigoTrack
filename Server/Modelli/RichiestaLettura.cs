using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Text.Json.Serialization;

namespace Server.Modelli
{
    public class RichiestaLetture
    {
        //identificativo del sensore di cui si vogliono leggere le misure
        [JsonPropertyName("sensor_id")]
        public string SensorId { get; set; } = "";

        //inizio dell’intervallo temporale richiesto
        [JsonPropertyName("inizio")]
        public string Inizio { get; set; } = "";

        //fine dell’intervallo temporale richiesto
        [JsonPropertyName("fine")]
        public string Fine { get; set; } = "";
    }
}
