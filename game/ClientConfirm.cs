namespace game;

public record ClientConfirm(int UserId, byte[] FingerprintProof) : Message;
