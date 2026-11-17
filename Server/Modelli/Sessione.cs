using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Server.Modelli
{
    public class Sessione
    {
        //chiave AES condivisa tra il client e il server per questa sessione
        public byte[] Chiave { get; set; } = Array.Empty<byte>();
    }
}
