using System.Security.Cryptography.X509Certificates;
using Anticheat;

namespace game;

public abstract record ClientState {
    private ClientState() {}

    public sealed record Connecting(Fingerprint Fingerprint, byte[]? TpmSecret, X509Certificate2? TpmCertificate, FingerprintChallenge Challenge) : ClientState; 
    public sealed record Connected : ClientState; 
}
