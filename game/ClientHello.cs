namespace game;

public record ClientHello(int UserId, byte[] Fingerprint) : Message;
