using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Microsoft.Extensions.Options;

namespace Amursoft.PasswordHasher
{
    public sealed class Pbkdf2PasswordHasher:IPasswordHasher
    {
        public byte Version { get; }
        public int Pbkdf2IterCount { get; }
        public int Pbkdf2SubkeyLength { get; }
        public int SaltSize { get; }
        
        public HashAlgorithmName HashAlgorithmName { get; }

        public Pbkdf2PasswordHasher(Pdkdf2PasswordHasherOptions opts)
        {
            Version = opts.Version;
            Pbkdf2IterCount = opts.Pbkdf2IterCount;   
            Pbkdf2SubkeyLength = opts.Pbkdf2SubkeyLength;   
            SaltSize = opts.SaltSize;
            HashAlgorithmName = opts.HashAlgorithmName;   
        }
        
        public Pbkdf2PasswordHasher(IOptionsMonitor<Pdkdf2PasswordHasherOptions> optsAccessor):
            this(optsAccessor.CurrentValue)
        {
        }

        
        public string HashPassword(string password)
        {
            if (password == null)
                throw new ArgumentNullException(nameof(password));

            byte[] salt;
            byte[] bytes;
            using (var rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, SaltSize, Pbkdf2IterCount, HashAlgorithmName))
            {
                salt = rfc2898DeriveBytes.Salt;
                bytes = rfc2898DeriveBytes.GetBytes(Pbkdf2SubkeyLength);
            }

            var inArray = new byte[1 + SaltSize + Pbkdf2SubkeyLength];
            inArray[0] = Version;
            Buffer.BlockCopy(salt, 0, inArray, 1, SaltSize);
            Buffer.BlockCopy(bytes, 0, inArray, 1 + SaltSize, Pbkdf2SubkeyLength);

            return Convert.ToBase64String(inArray);
        }

        public PasswordVerificationResult VerifyHashedPassword(string hashedPassword, string password)
        {
            if (password == null)
                throw new ArgumentNullException(nameof(password));

            if (hashedPassword == null)
                return PasswordVerificationResult.Failed;

            byte[] numArray = Convert.FromBase64String(hashedPassword);
            if (numArray.Length < 1)
                return PasswordVerificationResult.Failed;

            byte version = numArray[0];
            if (version > Version)
                return PasswordVerificationResult.Failed;

            byte[] salt = new byte[SaltSize];
            Buffer.BlockCopy(numArray, 1, salt, 0, SaltSize);
            byte[] a = new byte[Pbkdf2SubkeyLength];
            Buffer.BlockCopy(numArray, 1 + SaltSize, a, 0, Pbkdf2SubkeyLength);
            byte[] bytes;
            using (var rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, salt, Pbkdf2IterCount, HashAlgorithmName))
            {
                bytes = rfc2898DeriveBytes.GetBytes(Pbkdf2SubkeyLength);
            }

            if (FixedTimeEquals(a, bytes))
                return PasswordVerificationResult.Success;

            return PasswordVerificationResult.Failed;
        }

        // In .NET Core 2.1, you can use CryptographicOperations.FixedTimeEquals
        // https://github.com/dotnet/corefx/blob/a10890f4ffe0fadf090c922578ba0e606ebdd16c/src/System.Security.Cryptography.Primitives/src/System/Security/Cryptography/CryptographicOperations.cs#L32
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static bool FixedTimeEquals(byte[] left, byte[] right)
        {
            // NoOptimization because we want this method to be exactly as non-short-circuiting as written.
            // NoInlining because the NoOptimization would get lost if the method got inlined.
            if (left.Length != right.Length)
            {
                return false;
            }

            int length = left.Length;
            int accum = 0;

            for (int i = 0; i < length; i++)
            {
                accum |= left[i] - right[i];
            }

            return accum == 0;
        }
    }
}