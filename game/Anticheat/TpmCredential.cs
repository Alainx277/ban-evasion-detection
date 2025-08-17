using System;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Buffers.Binary;
using System.Numerics;

namespace Anticheat.TpmCredential
{
    public sealed class ActivationData
    {
            /// <summary>TPM2B_ENCRYPTED_SECRET – RSA‑OAEP encrypted seed</summary>
            public byte[] EncryptedSecret  { get; init; } = Array.Empty<byte>();

            /// <summary>Integrity HMAC over (encIdentity ∥ activatedName)</summary>
            public byte[] Integrity        { get; init; } = Array.Empty<byte>();

            /// <summary>encIdentity: AES‑CFB wrapped secretStruct</summary>
            public byte[] EncIdentity      { get; init; } = Array.Empty<byte>();
    }

    public static class TpmCredentialBlob
    {
        /// <summary>
        /// Creates a TPMS_ID_OBJECT + the accompanying encrypted seed.
        /// </summary>
        /// <param name="secret">Data that will be recovered inside the TPM (16‑64 bytes is typical).</param>
        /// <param name="activatedName">TPM name of the key that will do the ActivateCredential.</param>
        /// <param name="ekCertificate">Endorsement‑key certificate (DER or PEM, RSA‑2048/SHA‑256).</param>
        public static (X509Certificate2, ActivationData) Create(
            ReadOnlySpan<byte> secret,
            ReadOnlySpan<byte> activatedName,
            ReadOnlySpan<byte> ekCertificate)
        {
            // Get EK public key from certificate
            X509Certificate2 cert = X509CertificateLoader.LoadCertificate(ekCertificate);
            using RSA rsaPub             = cert.GetRSAPublicKey()
               ?? throw new InvalidOperationException("EK certificate does not contain an RSA key.");

            int rsaSizeBytes = rsaPub.KeySize / 8;

            // Generate the seed & encrypt with RSA‑OAEP ("IDENTITY")
            Span<byte> seed = stackalloc byte[16];
            RandomNumberGenerator.Fill(seed);

            byte[] encSeed = RsaOaepEncrypt(
                                rsaPub,
                                seed,
                                Encoding.ASCII.GetBytes("IDENTITY\0"),
                                HashAlgorithmName.SHA256,
                                rsaSizeBytes);

            // Build credential blob
            byte[] secret2B = ToTpm2B(secret);

            byte[] symKey = KDFa(
                HashAlgorithmName.SHA256,
                seed.ToArray(),
                "STORAGE",
                activatedName.ToArray(),
                Array.Empty<byte>(),
                128);

            // Encrypt secret using AES‑128 CFB with zero IV
            byte[] encIdentity = AesCfb128Encrypt(symKey, secret2B);

            byte[] hmacKey = KDFa(
                HashAlgorithmName.SHA256,
                seed.ToArray(),
                "INTEGRITY",
                Array.Empty<byte>(),
                Array.Empty<byte>(),
                256);

            // Integrity = HMAC(encIdentity || activatedName)
            byte[] integrity = Hmac(
                HashAlgorithmName.SHA256,
                hmacKey,
                Concat(encIdentity, activatedName.ToArray()));

            ActivationData activationData = new()
            {
                EncryptedSecret = encSeed,
                Integrity = integrity,
                EncIdentity = encIdentity
            };
            return (cert, activationData);
        }


        private static byte[] RsaOaepEncrypt(
            RSA rsa,
            ReadOnlySpan<byte> message,
            ReadOnlySpan<byte> label,
            HashAlgorithmName hashAlg,
            int modulusLength)
        {
            int hLen = HashLength(hashAlg);
            if (message.Length > modulusLength - 2 * hLen - 2)
                throw new ArgumentException("message too long for OAEP.");

            // OAEP ‑ RFC 8017, §7.1
            byte[] lHash = Hash(label, hashAlg);

            Span<byte> PS = stackalloc byte[modulusLength - message.Length - 2 * hLen - 2];
            PS.Clear();

            byte[] DB = Concat(lHash, PS.ToArray(), new byte[] { 0x01 }, message.ToArray());
            byte[] seed = Random(hLen);

            byte[] dbMask   = Mgf1(seed, modulusLength - hLen - 1, hashAlg);
            byte[] maskedDB = Xor(DB, dbMask);

            byte[] seedMask   = Mgf1(maskedDB, hLen, hashAlg);
            byte[] maskedSeed = Xor(seed, seedMask);

            byte[] EM = new byte[modulusLength];
            EM[0] = 0x00;
            Buffer.BlockCopy(maskedSeed, 0, EM, 1, hLen);
            Buffer.BlockCopy(maskedDB, 0, EM, 1 + hLen, maskedDB.Length);

            // raw RSA because we already applied OAEP
            return RawRsaEncrypt(rsa, EM);
        }

        static byte[] RawRsaEncrypt(RSA rsa, byte[] em)
        {
            // 1) pull out the public parameters
            var p = rsa.ExportParameters(false);
            BigInteger n = new BigInteger(p.Modulus!,   isBigEndian: true, isUnsigned: true);
            BigInteger e = new BigInteger(p.Exponent!,  isBigEndian: true, isUnsigned: true);

            // 2) interpret the padded message as a big‑endian integer
            BigInteger m = new BigInteger(em, isBigEndian: true, isUnsigned: true);

            // 3) c = m^e mod n
            BigInteger c = BigInteger.ModPow(m, e, n);

            // 4) turn it back into a fixed‑length byte[] of exactly k = KeySize/8 bytes
            int k = rsa.KeySize / 8;
            byte[] raw = c.ToByteArray(isBigEndian: true, isUnsigned: true);

            if (raw.Length == k)
                return raw;
            if (raw.Length < k)
                return new byte[k - raw.Length].Concat(raw).ToArray();
            // (overflow should never happen if m < n)
            return raw[^k..];
        }

        private static byte[] Mgf1(byte[] seed, int length, HashAlgorithmName hashAlg)
        {
            int hLen = HashLength(hashAlg);
            int counterMax = (int)Math.Ceiling(length / (double)hLen);
            byte[] mask = new byte[length];
            using IncrementalHash inc = IncrementalHash.CreateHMAC(hashAlg, Array.Empty<byte>()); // we’ll just flip the algorithm

            for (int c = 0; c < counterMax; c++)
            {
                byte[] ctr = BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder(c));
                byte[] data = Concat(seed, ctr);
                byte[] digest = Hash(data, hashAlg);
                int offset = c * hLen;
                Buffer.BlockCopy(digest, 0, mask, offset, Math.Min(hLen, length - offset));
            }
            return mask;
        }


        private static byte[] KDFa(
            HashAlgorithmName hashAlg,
            byte[] key,
            string label,
            byte[] contextU,
            byte[] contextV,
            int bits)
        {
            int hLen = HashLength(hashAlg);
            int loops = (bits + (hLen * 8) - 1) / (hLen * 8);
            byte[] result = new byte[loops * hLen];

            byte[] labelBytes = Encoding.ASCII.GetBytes(label);
            using HMAC hmac = HmacInstance(hashAlg, key);

            for (int i = 1; i <= loops; i++)
            {
                hmac.TryReset();
                hmac.WriteBE(i);                   // counter
                hmac.Write(labelBytes);            // label
                hmac.WriteByte(0x00);
                hmac.Write(contextU);
                hmac.Write(contextV);
                hmac.WriteBE(bits);                // “L”

                byte[] fragment = hmac.HashFinalReset();
                Buffer.BlockCopy(fragment, 0, result, (i - 1) * hLen, hLen);
            }

            return result.Take((bits + 7) / 8).ToArray();
        }



        private static byte[] AesCfb128Encrypt(byte[] key, byte[] data)
        {
            using Aes aes = Aes.Create();
            aes.Key         = key;
            aes.Mode        = CipherMode.CFB;   // .NET > 5, Windows 10 ; for older runtimes use AesCng
            aes.FeedbackSize= 128;
            aes.Padding     = PaddingMode.None;
            aes.IV          = new byte[16];     // all‑zero IV

            using ICryptoTransform xform = aes.CreateEncryptor();
            return xform.TransformFinalBlock(data, 0, data.Length);
        }

        private static byte[] Hash(ReadOnlySpan<byte> data, HashAlgorithmName alg)
        {
            IncrementalHash hash = IncrementalHash.CreateHash(alg);
            hash.AppendData(data);
            return hash.GetCurrentHash();
        }

        private static int HashLength(HashAlgorithmName alg) =>
            alg.Name switch
            {
                nameof(HashAlgorithmName.SHA1)   => 20,
                nameof(HashAlgorithmName.SHA256) => 32,
                nameof(HashAlgorithmName.SHA384) => 48,
                nameof(HashAlgorithmName.SHA512) => 64,
                _ => throw new NotSupportedException(alg.Name)
            };

        private static byte[] Hmac(HashAlgorithmName alg, byte[] key, byte[] data)
        {
            using HMAC h = HmacInstance(alg, key);
            return h.ComputeHash(data);
        }

        private static HMAC HmacInstance(HashAlgorithmName alg, byte[] key) =>
            alg.Name switch
            {
                nameof(HashAlgorithmName.SHA1)   => new HMACSHA1(key),
                nameof(HashAlgorithmName.SHA256) => new HMACSHA256(key),
                nameof(HashAlgorithmName.SHA384) => new HMACSHA384(key),
                nameof(HashAlgorithmName.SHA512) => new HMACSHA512(key),
                _ => throw new NotSupportedException()
            };

        private static byte[] ToTpm2B(ReadOnlySpan<byte> data)
        {
            byte[] outBuf = new byte[2 + data.Length];
            BinaryPrimitives.WriteUInt16BigEndian(outBuf.AsSpan(0, 2), (ushort)data.Length);
            data.CopyTo(outBuf.AsSpan(2));
            return outBuf;
        }

        private static byte[] Random(int count)
        {
            byte[] r = new byte[count];
            RandomNumberGenerator.Fill(r);
            return r;
        }

        private static byte[] Concat(params byte[][] arrays)
        {
            int len = arrays.Sum(a => a.Length);
            byte[] res = new byte[len];
            int pos = 0;
            foreach (var a in arrays)
            {
                Buffer.BlockCopy(a, 0, res, pos, a.Length);
                pos += a.Length;
            }
            return res;
        }

        private static byte[] Xor(byte[] a, byte[] b)
        {
            byte[] r = new byte[a.Length];
            for (int i = 0; i < a.Length; i++)
                r[i] = (byte)(a[i] ^ b[i]);
            return r;
        }
    }

    internal static class HashExtensions
    {
        public static void Write(this HMAC h, ReadOnlySpan<byte> data) =>
            h.TransformBlock(data.ToArray(), 0, data.Length, null, 0);

        public static void WriteBE(this HMAC h, int i)
        {
            Span<byte> tmp = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(tmp, (uint)i);
            h.Write(tmp);
        }

        public static void WriteByte(this HMAC h, byte b)
        {
            Span<byte> tmp = [b];
            h.Write(tmp);
        }

        public static byte[] HashFinalReset(this HMAC h)
        {
            h.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            byte[] digest = h.Hash!;
            h.Initialize();
            return digest;
        }

        public static void TryReset(this HMAC h)
        {
            h.Initialize();
        }
    }
}
