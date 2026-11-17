using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Text.Json.Serialization;

public class RichiestaLettureClient
{
    //sensore da consultare e intervallo di date richiesto
    [JsonPropertyName("sensor_id")]
    public string SensorId { get; set; } = "";

    [JsonPropertyName("inizio")]
    public string Inizio { get; set; } = "";

    [JsonPropertyName("fine")]
    public string Fine { get; set; } = "";
}

