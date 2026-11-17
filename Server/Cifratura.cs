
using System.Security.Cryptography;
using System.Text;

public class Cifratura
{
    //cifra un messaggio con AES-GCM
    //AES-GCM cifra il messaggio e restituisce i dati cifrati insieme al tag
    public static (string Cifrato, string Tag) Cifra(string messaggio, byte[] chiave)
    {
        //genera un nonce casuale, necessario per AES-GCM
        byte[] nonce = RandomNumberGenerator.GetBytes(12);

        //trasforma il testo in una sequenza di byte
        byte[] dati = Encoding.UTF8.GetBytes(messaggio);
        byte[] datiCifrati = new byte[dati.Length];
        byte[] tag = new byte[16];

        //cifra i dati e genera il tag di autenticazione
        //se il tag non corrisponde, AES-GCM genera un errore
        using (AesGcm aes = new AesGcm(chiave, 16))
        {
            aes.Encrypt(nonce, dati, datiCifrati, tag);
        }

        //unisce nonce e testo cifrato per poterli trasmettere insieme
        byte[] busta = new byte[nonce.Length + datiCifrati.Length];

        Buffer.BlockCopy(nonce, 0, busta, 0, nonce.Length);
        Buffer.BlockCopy(datiCifrati, 0, busta, nonce.Length, datiCifrati.Length);

        return (
            Convert.ToBase64String(busta),
            Convert.ToBase64String(tag)
        );
    }

  
    //decifra il messaggio e controlla il tag di autenticazione
    public static string Decifra(string testoCifrato, string tagBase64, byte[] chiave)
    {
        byte[] busta = Convert.FromBase64String(testoCifrato);
        byte[] tag = Convert.FromBase64String(tagBase64);

        if (busta.Length < 12 || tag.Length != 16)
        {
            throw new CryptographicException("Busta cifrata non valida.");
        }

        //recupera il nonce e i dati cifrati dalla busta
        byte[] nonce = busta[..12];
        byte[] datiCifrati = busta[12..];

        byte[] dati = new byte[datiCifrati.Length];

        using (AesGcm aes = new AesGcm(chiave, 16))
        {
            aes.Decrypt(nonce, datiCifrati, tag, dati);
        }

        return Encoding.UTF8.GetString(dati);
    }
}
