#pragma once

#include "include/sodium.h"
#include "generated/fingerprint.pb.h"

using namespace anticheat;

using Seed  = std::array<uint8_t, crypto_sign_SEEDBYTES>;
using PublicKey  = std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>;
using PrivateKey  = std::array<uint8_t, crypto_sign_SECRETKEYBYTES>;

std::pair<PublicKey,PrivateKey> derive_keypair_from_bytes(const std::string& raw);
