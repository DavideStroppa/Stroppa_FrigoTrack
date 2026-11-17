using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Text.Json.Serialization;

namespace Client.Sensori
{
    public class Sensore
    {
        //identificativo del sensore e tipo di merce che trasporta
        public string Id { get; set; }
        public string TipoMerce { get; set; }

        //imposta i dati iniziali del sensore
        public Sensore(string id, string tipoMerce)
        {
            Id = id;
            TipoMerce = tipoMerce;
        }

        //genera una misurazione casuale
        public MisurazioneClient GeneraMisurazione()
        {
            //variabile che conterrà la temperatura generata
            double temperatura;

            //genera temperature diverse in base al tipo di merce
            if (TipoMerce == "pharma")
            {
                temperatura = Random.Shared.Next(20, 81) / 10.0;
            }
            else if (TipoMerce == "food")
            {
                temperatura = Random.Shared.Next(10, 81) / 10.0;
            }
            else
            {
                temperatura = Random.Shared.Next(-250, -179) / 10.0;
            }

            //crea la misurazione con tutti i dati del sensore
            return new MisurazioneClient
            {
                SensorId = Id,
                Timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                CargoType = TipoMerce,
                Temperatura = temperatura,
                Umidita = Random.Shared.Next(30, 81),
                Batteria = Random.Shared.Next(60, 101)
            };
        }
    }

    public class MisurazioneClient
    {
        //nomi JSON uguali a quelli previsti dallo schema
        [JsonPropertyName("sensor_id")]
        public string SensorId { get; set; } = "";

        [JsonPropertyName("timestamp")]
        public string Timestamp { get; set; } = "";

        [JsonPropertyName("cargo_type")]
        public string CargoType { get; set; } = "";

        [JsonPropertyName("temperature_c")]
        public double Temperatura { get; set; }

        [JsonPropertyName("humidity")]
        public double Umidita { get; set; }

        [JsonPropertyName("battery")]
        public int Batteria { get; set; }
    }
}
