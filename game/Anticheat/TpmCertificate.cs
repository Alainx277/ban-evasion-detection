using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Anticheat;

class TpmCertificate
{
    public static bool Verify(X509Certificate2 ekCert, byte[][] embeddedChain, X509Certificate2Collection trustedRoots)
    {
        // Set up the chain with custom trusted roots
        using var chain = new X509Chain();
        // Use only the custom root store (ignore system root store for this verification)
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Clear();
        chain.ChainPolicy.CustomTrustStore.AddRange(trustedRoots);

        // Add any certificates that are embedded in the TPM (newer Intel CPUs)
        foreach (var item in embeddedChain)
        {
            X509Certificate2 chainCert = X509CertificateLoader.LoadCertificate(item);
            Console.WriteLine($"Adding cert chain member: {chainCert}");
            // Make sure we are not adding any root certificates
            if (ekCert.Issuer == ekCert.Subject)
            {
                Console.WriteLine($"TPM embedded chain contains root certificate, this makes it impossible to verify and shouldn't happen");
                return false;
            }
            chain.ChainPolicy.ExtraStore.Add(chainCert);
        }

        // Enable revocation checking (online if possible)
        chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;

        // Ignore errors during revocation checking, not all manufacturers provide standardized revocation endpoints
        chain.ChainPolicy.VerificationFlags =
            X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown | X509VerificationFlags.IgnoreCtlSignerRevocationUnknown | X509VerificationFlags.IgnoreEndRevocationUnknown;

        // Attempt to build the chain
        var zoneBuild = game.Profiler.BeginZone("Build chain");
        bool isChainValid = chain.Build(ekCert);
        zoneBuild.Dispose();
        if (!isChainValid)
        {
            // Chain build failed, certificate is not trusted
            foreach (X509ChainStatus status in chain.ChainStatus)
            {
                Console.WriteLine($"Chain error: {status.StatusInformation.Trim()} (Status: {status.Status})");
            }
            return false;
        }

        // To ensure we did not get a valid certificate but with a non-TPM purpose (for example a website certificate)
        // we check that the certificate has the TPM EK Certificate OID (2.23.133.8.1) in Extended Key Usage or Certificate Policies
        bool hasEkCertOid = false;
        const string TcgEkCertOid = "2.23.133.8.1";
        foreach (X509Extension ext in ekCert.Extensions)
        {
            if (ext is X509EnhancedKeyUsageExtension ekuExt)
            {
                foreach (Oid oid in ekuExt.EnhancedKeyUsages)
                {
                    if (oid.Value == TcgEkCertOid)
                    {
                        hasEkCertOid = true;
                        break;
                    }
                }
            }
            if (hasEkCertOid) break;
        }

        if (!hasEkCertOid)
        {
            Console.WriteLine("EK certificate is missing the TPM EK Certificate OID (2.23.133.8.1).");
            return false;
        }

        return true;
    }
}

class TpmCertificateAuthorities
{
    /// <summary>
    /// Loads all self-signed root certificates (.cer/.crt) from the specified ZIP archive.
    /// </summary>
    /// <param name="zipFilePath">Path to the ZIP file containing certificate files.</param>
    /// <returns>A collection of trusted root certificates.</returns>
    public static X509Certificate2Collection Load(string zipFilePath)
    {
        var trustedRoots = new X509Certificate2Collection();

        // Open the ZIP archive for reading
        using (FileStream zipStream = File.OpenRead(zipFilePath))
        using (var archive = new ZipArchive(zipStream, ZipArchiveMode.Read, leaveOpen: false))
        {
            foreach (var entry in archive.Entries)
            {
                // Only consider files with .cer or .crt extensions
                if (entry.Length > 0 &&
                    (entry.Name.EndsWith(".cer", StringComparison.OrdinalIgnoreCase) ||
                     entry.Name.EndsWith(".crt", StringComparison.OrdinalIgnoreCase)))
                {
                    try
                    {
                        // Read the entry into a byte array
                        byte[] rawData;
                        using (var entryStream = entry.Open())
                        using (var ms = new MemoryStream())
                        {
                            entryStream.CopyTo(ms);
                            rawData = ms.ToArray();
                        }

                        // Create the certificate object
                        X509Certificate2 cert = X509CertificateLoader.LoadCertificate(rawData);

                        trustedRoots.Add(cert);
                    }
                    catch (CryptographicException ex)
                    {
                        Console.WriteLine($"Failed to load cert from ZIP entry '{entry.FullName}': {ex.Message}");
                    }
                    catch (InvalidDataException ex)
                    {
                        Console.WriteLine($"Invalid ZIP entry '{entry.FullName}': {ex.Message}");
                    }
                }
            }
        }

        return trustedRoots;
    }
}
