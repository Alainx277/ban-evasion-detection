
namespace game;

public record ServerHello(byte[] FingerprintChallenge) : Message;
