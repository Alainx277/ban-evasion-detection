#pragma once

#include "generated/fingerprint.pb.h"

using namespace anticheat;

// https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/tpm-key-attestation
// https://www.gradenegger.eu/en/determining-and-exporting-a-trusted-platform-module-tpm-endorsement-certificate/

Fingerprint make_fingerprint();
FingerprintProof make_proof(FingerprintChallenge& challenge, uint32_t userId);

bool tpm_certificates(Fingerprint &fp);
bool tpm_fingerprint(Fingerprint& fp);
bool tpm_proof(FingerprintProof &fp, FingerprintChallenge &challenge);
bool registry_trace(Fingerprint& fp) noexcept;
bool wmi_fingerprint(Fingerprint& fp);
bool arp_fingerprint(Fingerprint& fp, std::size_t n) noexcept;
bool kernel_fingerprint(Fingerprint& fp);
