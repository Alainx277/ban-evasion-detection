using System;
using System.IO;
using System.Security.Cryptography;
using Google.Protobuf;
using Google.Protobuf.Collections;
using NSec.Cryptography;

namespace Anticheat;

public static class FingerprintVerifier
{
    /// <summary>
    /// Verifies every detached signature in <paramref name="proof" /> against the
    /// messages in <paramref name="issuedChallenge" /> and the Ed25519 public
    /// keys in <paramref name="clientFingerprint" />.
    /// </summary>
    /// <returns>True if all signatures are valid; false otherwise.</returns>
    public static bool Verify(
        int userId,
        Fingerprint clientFingerprint,
        FingerprintChallenge issuedChallenge,
        FingerprintProof proof)
    {
        byte[] user = BitConverter.GetBytes(userId);

        // Scalar fields
        if (!VerifySig(user, issuedChallenge.RegistryKey, proof.RegistryKey, clientFingerprint.RegistryKey)) return false;
        if (!VerifySig(user, issuedChallenge.CpuSerial, proof.CpuSerial, clientFingerprint.CpuSerial)) return false;
        if (!VerifySig(user, issuedChallenge.BiosSerial, proof.BiosSerial, clientFingerprint.BiosSerial)) return false;

        // Repeated fields
        if (!VerifyRepeated(user, issuedChallenge.MonitorIds, proof.MonitorIds, clientFingerprint.MonitorIds)) return false;
        if (!VerifyRepeated(user, issuedChallenge.MacAddresses, proof.MacAddresses, clientFingerprint.MacAddresses)) return false;
        if (!VerifyRepeated(user, issuedChallenge.DiskSerials, proof.DiskSerials, clientFingerprint.DiskSerials)) return false;
        if (!VerifyRepeated(user, issuedChallenge.VolumeSerials, proof.VolumeSerials, clientFingerprint.VolumeSerials)) return false;

        return true;
    }

    private static bool VerifySig(byte[] userId, ByteString message, ByteString signature, ByteString publicKey)
    {
        // Add userId to the challenge to prevent relay attack
        byte[] combined = new byte[userId.Length + message.Length];
        Buffer.BlockCopy(userId, 0, combined, 0, userId.Length);
        message.CopyTo(combined, userId.Length);

        var pk = PublicKey.Import(SignatureAlgorithm.Ed25519, publicKey.Span, KeyBlobFormat.RawPublicKey);
        return SignatureAlgorithm.Ed25519.Verify(pk, combined, signature.Span);
    }

    private static bool VerifyRepeated(
        byte[] userId,
        RepeatedField<ByteString> messages,
        RepeatedField<ByteString> signatures,
        RepeatedField<ByteString> publicKeys)
    {
        if (messages.Count != signatures.Count || signatures.Count != publicKeys.Count)
        {
            return false;
        }

        for (int i = 0; i < messages.Count; i++)
        {
            if (!VerifySig(userId, messages[i], signatures[i], publicKeys[i]))
            {
                return false;
            }
        }
        return true;
    }
}
