using System.Security.Cryptography;

namespace Amursoft.PasswordHasher
{
    public class Pdkdf2PasswordHasherOptions
    {
        public byte Version { get; set; } = 1;
        public int Pbkdf2IterCount { get; set; } = 1000;
        public int Pbkdf2SubkeyLength { get; set; } = 256 / 8; // 256 bits
        public int SaltSize { get; set; } = 128 / 8; // 128 bits
        
        public HashAlgorithmName HashAlgorithmName { get; set; } = HashAlgorithmName.SHA256;
    }
}