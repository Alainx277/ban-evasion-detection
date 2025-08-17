#include "stdafx.h"
#include "crypto.h"

// We use an empty salt to create a deterministic derivation from the hardware identifier
// This makes the protocol vulnerable to precomputation attacks, which we try to mitigate by
// increasing the difficulty using Argon2
unsigned char salt[crypto_pwhash_SALTBYTES] = {};

std::pair<PublicKey,PrivateKey> derive_keypair_from_bytes(const std::string& raw) {
    // Hash the data using an expensive hash function to make bruteforcing the underlying hardware ids harder
    Seed seed;
    // Using INTERACTIVE setting: This requires 64 MiB of dedicated RAM and takes about 0.7 seconds on a 2.8 GHz Core i7 CPU.
    crypto_pwhash(seed.data(), seed.size(), raw.data(), raw.size(), salt, crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_ARGON2ID13);

    // Turn that seed into an Ed25519 keypair
    PublicKey pub;
    PrivateKey priv;
    crypto_sign_seed_keypair(pub.data(), priv.data(), seed.data());

    return {pub, priv};
}
