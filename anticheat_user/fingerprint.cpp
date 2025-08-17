#include "stdafx.h"
#include <WbemCli.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <comdef.h>
#include <cmath>
#include <tracy/Tracy.hpp>

#include "fingerprint.h"
#include "../anticheat_kernel/fingerprint_defs.h"
#include "crypto.h"
#include "Tpm2.h"
#include "uuidv7.h"
#include "base64.hpp"

using namespace TpmCpp;

class FingerprintPrivate {
public:
    PrivateKey registryKey;
    PrivateKey cpuSerial;
    PrivateKey biosSerial;

    std::vector<PrivateKey> monitorIds{};
    std::vector<PrivateKey> macAddresses{};
    std::vector<PrivateKey> diskSerials{};
    std::vector<PrivateKey> volumeSerials{};
};
FingerprintPrivate fingerprintPrivate{};

template <
    typename StringSeq,
    typename PrivContainer
>
void derive_keys(StringSeq& serials, PrivContainer& privOut) {
    for (auto& s : serials) {
        auto keypair = derive_keypair_from_bytes(s);
        auto pub = keypair.first;
        auto fingerprintPrivate = keypair.second;
        // Overwrite the serial with the public key bytes
        s.assign(pub.begin(), pub.end());
        // Store the private key
        privOut.emplace_back(std::move(fingerprintPrivate));
    }
}

template <
    typename StringPtr,
    typename PrivRef
>
void derive_key(StringPtr serialPtr, PrivRef& privOut) {
    auto keypair = derive_keypair_from_bytes(*serialPtr);
    auto pub = keypair.first;
    auto fingerprintPrivate = keypair.second;
    // Overwrite the original serial with the public key bytes
    serialPtr->assign(pub.begin(), pub.end());
    // Store the private key
    privOut = std::move(fingerprintPrivate);
}

// Post with basically all ways to fingerprint https://www.unknowncheats.me/forum/anti-cheat-bypass/333662-methods-retrieving-unique-identifiers-hwids-pc.html

Fingerprint make_fingerprint()
{
    ZoneScopedN("Fingerprint create");

    Fingerprint fp{};
    if (!registry_trace(fp))
    {
        printf("Failed registry trace\n");
    }

    if (!kernel_fingerprint(fp))
    {
        printf("Failed kernel fingerprint\n");
    }

    if (!tpm_certificates(fp))
    {
        printf("Failed TPM certificates\n");
    }
    try
    {
        if (!tpm_fingerprint(fp))
        {
            printf("Failed TPM fingerprint\n");
        }
    }
    catch (const std::exception &e)
    {
        printf("Failed TPM fingerprint: %s\n", e.what());
    }

    if (!wmi_fingerprint(fp))
    {
        printf("Failed WMI fingerprint\n");
    }

    if (!arp_fingerprint(fp, 5))
    {
        printf("Failed ARP fingerprint\n");
    }

    FingerprintPrivate privateKeys{};
    {
    ZoneScopedN("Key derivation");
    uint64_t total = 3 + fp.monitorids_size() + fp.macaddresses_size() + fp.diskserials_size() + fp.volumeserials_size();
    uint64_t generated = 0;
    printf("Generating %llu fingerprint signature keys...\n", total);
    derive_keys(*fp.mutable_monitorids(), privateKeys.monitorIds);
    generated += fp.monitorids_size();
    printf("%llu%% ", std::llround((static_cast<float>(generated) / total) * 100));
    derive_keys(*fp.mutable_macaddresses(), privateKeys.macAddresses);
    generated += fp.macaddresses_size();
    printf("%llu%% ", std::llround((static_cast<float>(generated) / total) * 100));
    derive_keys(*fp.mutable_diskserials(), privateKeys.diskSerials);
    generated += fp.diskserials_size();
    printf("%llu%% ", std::llround((static_cast<float>(generated) / total) * 100));
    derive_keys(*fp.mutable_volumeserials(), privateKeys.volumeSerials);
    generated += fp.volumeserials_size();
    printf("%llu%% ", std::llround((static_cast<float>(generated) / total) * 100));

    derive_key(fp.mutable_registrykey(), privateKeys.registryKey);
    derive_key(fp.mutable_cpuserial(), privateKeys.cpuSerial);
    if (!fp.kernelbiosserial().empty()) { derive_key(fp.mutable_kernelbiosserial(), privateKeys.biosSerial); }
    derive_key(fp.mutable_biosserial(), privateKeys.biosSerial);
    printf("100%%\n");
    }

    fingerprintPrivate = privateKeys;
    printf("Finished generating fingerprint signature keys\n");

    return fp;
}

FingerprintProof make_proof(FingerprintChallenge &challenge, uint32_t userId)
{
    ZoneScopedN("Fingerprint prove");
    FingerprintProof proof{};
    if (!challenge.tpmchallenge().empty()) {
        try
        {
            if (!tpm_proof(proof, challenge))
            {
                printf("Failed TPM proof\n");
            }
        }
        catch (const std::exception &e)
        {
            printf("Failed TPM proof: %s", e.what());
        }
    }

    auto sign = [&](const std::string& msg, const PrivateKey& key) {
        unsigned char sig[crypto_sign_BYTES];
        unsigned long long siglen;

        // Concatenate with userId to prevent relay attack
        std::string buffer;
        buffer.reserve(4 + msg.size());
        buffer.append(reinterpret_cast<char*>(&userId), 4);
        buffer.append(msg);

        if (crypto_sign_detached(sig, &siglen, reinterpret_cast<const unsigned char*>(buffer.data()), buffer.size(), key.data()) != 0) {
            throw std::runtime_error("Signature generation failed");
        }
        return std::string(reinterpret_cast<char*>(sig), siglen);
    };

    // Create signatures for all the challenges

    {
    ZoneScopedN("Signatures");
    printf("Signing identifier challenges...\n");
    proof.set_registrykey(sign(challenge.registrykey(), fingerprintPrivate.registryKey));
    proof.set_cpuserial(sign(challenge.cpuserial(), fingerprintPrivate.cpuSerial));
    proof.set_biosserial(sign(challenge.biosserial(), fingerprintPrivate.biosSerial));

    if (challenge.monitorids_size() != fingerprintPrivate.monitorIds.size()) {
        throw std::runtime_error("monitorIds size mismatch");
    }
    for (int i = 0; i < challenge.monitorids_size(); ++i) {
        proof.add_monitorids(
            sign(challenge.monitorids(i), fingerprintPrivate.monitorIds[i]));
    }

    if (challenge.macaddresses_size() != fingerprintPrivate.macAddresses.size()) {
        throw std::runtime_error("macAddresses size mismatch");
    }
    for (int i = 0; i < challenge.macaddresses_size(); ++i) {
        proof.add_macaddresses(
            sign(challenge.macaddresses(i), fingerprintPrivate.macAddresses[i]));
    }

    if (challenge.diskserials_size() != fingerprintPrivate.diskSerials.size()) {
        throw std::runtime_error("diskSerials size mismatch");
    }
    for (int i = 0; i < challenge.diskserials_size(); ++i) {
        proof.add_diskserials(
            sign(challenge.diskserials(i), fingerprintPrivate.diskSerials[i]));
    }

    if (challenge.volumeserials_size() != fingerprintPrivate.volumeSerials.size()) {
        throw std::runtime_error("volumeSerials size mismatch");
    }
    for (int i = 0; i < challenge.volumeserials_size(); ++i) {
        proof.add_volumeserials(
            sign(challenge.volumeserials(i), fingerprintPrivate.volumeSerials[i]));
    }
    }
    printf("Finished signing\n");

    return proof;
}

static const TPMT_SYM_DEF_OBJECT Aes128Cfb{TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB};

static bool run_command_base64(
    const std::string& psCommand,
    const std::function<void(const std::string&)>& adder
) {
    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
    HANDLE childOutRead = nullptr, childOutWrite = nullptr;
    if (!CreatePipe(&childOutRead, &childOutWrite, &sa, 0)) {
        printf("CreatePipe failed: %lu\n", GetLastError());
        return false;
    }
    SetHandleInformation(childOutRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFO si = { sizeof(si) };
    si.dwFlags      = STARTF_USESTDHANDLES;
    si.hStdOutput   = childOutWrite;
    si.hStdError    = childOutWrite;
    si.hStdInput    = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi;
    BOOL ok = CreateProcess(
        nullptr,
        const_cast<LPSTR>(psCommand.c_str()),
        nullptr, nullptr,
        TRUE,
        0,
        nullptr,
        nullptr,
        &si,
        &pi
    );
    CloseHandle(childOutWrite);
    if (!ok) {
        printf("CreateProcess failed: %lu\n", GetLastError());
        CloseHandle(childOutRead);
        return false;
    }

    std::vector<char> buffer;
    std::array<char, 4096> chunk;
    DWORD bytesRead;
    while (ReadFile(childOutRead, chunk.data(), (DWORD)chunk.size(), &bytesRead, nullptr) && bytesRead) {
        buffer.insert(buffer.end(), chunk.data(), chunk.data() + bytesRead);
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 0;
    if (!GetExitCodeProcess(pi.hProcess, &exitCode) || exitCode != 0) {
        printf("Child exited %lu, skipping parse\n", exitCode);
        CloseHandle(childOutRead);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return false;
    }

    CloseHandle(childOutRead);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // Split on lines, decode each non-empty one
    std::istringstream outStr(std::string(buffer.begin(), buffer.end()));
    std::string line;
    while (std::getline(outStr, line)) {
        if (line.size() < 3) continue;
        auto decoded = base64::decode(line);
        adder(decoded);
    }

    return true;
}

bool tpm_certificates(Fingerprint &fp) {
    ZoneScopedN("TPM certificates");
    std::string manufacturerCommand = TEXT("powershell -command \"$now = Get-Date; $bytes = (Get-TpmEndorsementKeyInfo).ManufacturerCertificates | ?{$_} | % Export Cert; if ($null -ne $bytes) { [Convert]::ToBase64String($bytes) }\"");
    bool ok = run_command_base64(manufacturerCommand, [&](auto& cert) { fp.add_manufacturercertificates(cert); });
    std::string additionalCommand = TEXT("powershell -command \"$now = Get-Date; $bytes = (Get-TpmEndorsementKeyInfo).AdditionalCertificates | ?{$_} | % Export Cert; if ($null -ne $bytes) { [Convert]::ToBase64String($bytes) }\"");
    ok = run_command_base64(additionalCommand, [&](auto& cert) { fp.add_additionalcertificates(cert); }) && ok;

    return ok;
}

void PrintHex(const std::vector<BYTE>& data, const char* prefix = nullptr) {
    if (prefix) {
        printf("%s", prefix);
    }
    for (size_t i = 0; i < data.size(); ++i) {
        // %02X prints two-digit uppercase hex, zero-padded
        printf("%02X", data[i]);
        // optional: add a space between bytes
        if (i + 1 < data.size()) printf(" ");
    }
    printf("\n");
}

static constexpr std::array<uint8_t,32> ekPolicyDigest = {
    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8,
    0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7, 0x24,
    0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
    0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA
};

TPM_HANDLE keyToActivate;
TpmTbsDevice tpmDevice;
Tpm2 tpm{};

// Reads any certificate chain entries from the TPM
static ByteVec read_nv_ek_cert_chain(Tpm2& tpm)
{
    ByteVec chain;

    for (UINT32 idx = 0x01c00100; idx <= 0x01c001ff; ++idx)
    {
        TPM_HANDLE nvHandle(idx);

        try
        {
            // Will throw TpmException if the index is not defined
            auto nvPub = tpm.NV_ReadPublic(nvHandle);

            const UINT16 totalSize = nvPub.nvPublic.dataSize;
            UINT16 offset = 0;

            while (offset < totalSize)
            {
                const UINT16 chunk = std::min<UINT16>(totalSize - offset, 1024);
                ByteVec part = tpm.NV_Read(nvHandle, nvHandle, chunk, offset);
                chain.insert(chain.end(), part.begin(), part.end());
                offset += chunk;
            }
        }
        catch (...)
        {
            // Stop looking on error
            break;
        }
    }
    return chain;
}

static std::vector<ByteVec> split_certificate_chain(const ByteVec& chain)
{
    std::vector<ByteVec> certs;

    size_t i = 0;
    const size_t n = chain.size();

    while (i + 4 <= n)
    {
        if (chain[i] != 0x30) { ++i; continue; }

        size_t hdr = 2;
        size_t len = 0;
        uint8_t l = chain[i + 1];

        if (l < 0x80) {
            len = l;
        }
        else if (l == 0x81 && i + 2 < n) {
            len = chain[i + 2];  hdr = 3;
        }
        else if (l == 0x82 && i + 3 < n) {
            len = (chain[i + 2] << 8) | chain[i + 3];  hdr = 4;
        }
        else if (l == 0x83 && i + 4 < n) {
            len = (chain[i + 2] << 16) | (chain[i + 3] << 8) | chain[i + 4];
            hdr = 5;
        }
        else { ++i; continue; }

        const size_t total = hdr + len;
        if (total == 0 || i + total > n) { ++i; continue; }

        // Heuristic sanity check
        if (len < 128 || len > 10000) { ++i; continue; }

        certs.emplace_back(chain.begin() + i, chain.begin() + i + total);
        i += total;
    }
    return certs;
}

// Time attestation: https://lpc.events/event/7/contributions/740/attachments/654/1203/A-Ridiculiously-Short-Intro-into-Device-Attestation-Final.pdf
// Could be used to flag players that have a new TPM (example bought a new one to bypass ban)
// Great overview of full attestation protocol https://community.infineon.com/t5/Blogs/TPM-remote-attestation-How-can-I-trust-you/ba-p/452729#.
bool tpm_fingerprint(Fingerprint &fp)
{
    ZoneScopedN("TPM");
    printf("About to do TPM\n");
    tpmDevice = TpmTbsDevice();
    if (tpmDevice.Connect())
    {
        printf("device connected\n");
    }
    else
    {
        printf("device failed to connect\n");
    }
    tpm._SetDevice(tpmDevice);

    // We simulate a remote attestation procedure with a privacy CA because
    // the endorsement key (EK) can normally not be used to decrypt or encrypt data.
    // So instead we will generate a temporary siging key which will allow us to use the EK.
    // In the intended scenario the privacy CA is a trusted party that will receive the identity (EK pub) of the TPM.
    // In this case it will be our own game server instead.

    // Construct certificate chain if present in the TPM
    // Required on newer Intel CPUs
    ByteVec certChain = read_nv_ek_cert_chain(tpm);
    printf("Cert chain has %d members\n", certChain.size());
    for (const ByteVec& cert : split_certificate_chain(certChain)){
        fp.add_certificatechain(std::string(cert.begin(), cert.end()));
    }

    // TCG TPM v2.0 Provisioning Guidance 7.8 NV Memory EK Reserved Handle
    TPM_HANDLE ekHandle(0x81010001);
    // Get the public key of the EK
    auto ekPubX = tpm.ReadPublic(ekHandle);
    ekHandle.SetName(ekPubX.outPublic.GetName());
    ekHandle.SetAuth(ByteVec{});
    TPMT_PUBLIC &ekPub = ekPubX.outPublic;
    auto ekString = ekPub.ToString(true);

    printf("EK PUB:\n%s\n\n", ekString.c_str());

    AUTH_SESSION policy = tpm.StartAuthSession(
                            TPM_SE::POLICY,
                            ekPub.nameAlg);
    printf("Created auth session\n");
    // Satisfy PolicySecret with the endorsement hierarchy.
    // -> auth for TPM_RH_ENDORSEMENT is empty on almost all PCs
    tpm.PolicySecret(TPM_RH::ENDORSEMENT, policy,
                    ByteVec{}, ByteVec{}, ByteVec{}, 0);
    printf("Created policy secret\n");

    TPMT_PUBLIC akTemplate(
            ekPub.nameAlg,
            TPMA_OBJECT::sign | TPMA_OBJECT::restricted |
            TPMA_OBJECT::fixedTPM | TPMA_OBJECT::fixedParent |
            TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth,
            ByteVec{},                                   // no auth‑policy
            TPMS_RSA_PARMS(
                TPMT_SYM_DEF_OBJECT{},                   // no symmetric alg
                TPMS_SCHEME_RSASSA(ekPub.nameAlg),
                2048,
                65537),
            TPM2B_PUBLIC_KEY_RSA());

    auto akParts = tpm._Sessions(policy).Create(ekHandle,
                              TPMS_SENSITIVE_CREATE{},    // empty userAuth
                              akTemplate,
                              ByteVec{},                  // outsideInfo
                              std::vector<TPMS_PCR_SELECTION>{});
    printf("Generated key to activate\n");
    tpm.FlushContext(policy);

    auto policy2 = tpm.StartAuthSession(
        TPM_SE::POLICY, ekPub.nameAlg);
    tpm.PolicySecret(TPM_RH::ENDORSEMENT, policy2,
                    {}, {}, {}, 0);
    keyToActivate = tpm._Sessions(policy2).Load(ekHandle,
                                   akParts.outPrivate,
                                   akParts.outPublic);

    keyToActivate.SetName(akParts.outPublic.GetName());
    keyToActivate.SetAuth(ByteVec{});
    auto activateString = akParts.outPublic.ToString(true);
    printf("ACTIVATE KEY:\n%s\n\n", activateString.c_str());

    auto keyName = keyToActivate.GetName();
    fp.set_derivedkeyname(std::string(keyName.begin(), keyName.end()));

    return true;
}

bool tpm_proof(FingerprintProof &fp, FingerprintChallenge &challenge)
{
    ZoneScopedN("TPM prove");

    // TCG TPM v2.0 Provisioning Guidance 7.8 NV Memory EK Reserved Handle
    TPM_HANDLE ekHandle(0x81010001);
    // Get the public key of the EK
    auto ekPubX = tpm.ReadPublic(ekHandle);
    ekHandle.SetName(ekPubX.outPublic.GetName());
    ekHandle.SetAuth(ByteVec{});
    TPMT_PUBLIC &ekPub = ekPubX.outPublic;
    auto ekString = ekPub.ToString(true);

    AUTH_SESSION policy = tpm.StartAuthSession(
                            TPM_SE::POLICY,
                            TPM_ALG_ID::SHA256);            // hash must match EK nameAlg
    // We don't send the policy command code ActivateCredential because most implementations
    // don't actually require it and won't work if its used.
    printf("Created activate auth session\n");
    tpm.PolicySecret(TPM_RH::ENDORSEMENT, policy,
                    ByteVec{}, ByteVec{}, ByteVec{}, 0);
    printf("Set activate policy secret\n");


    //  Prepare the second session: a simple PW session for the AIK handle
    AUTH_SESSION pw = AUTH_SESSION::PWAP();

    // Get the encrypted data from the server
    ActivationData cred{};
    cred.Secret = ByteVec(challenge.tpmsecret().begin(), challenge.tpmsecret().end());
    cred.CredentialBlob = TPMS_ID_OBJECT(
        ByteVec(challenge.tpmintegrity().begin(), challenge.tpmintegrity().end()),
        ByteVec(challenge.tpmchallenge().begin(), challenge.tpmchallenge().end())
    );

    // We use our EK to decrypt the server challenge, proving that we own the EK private key
    // Run activate credential with both sessions
    ByteVec decryptedChallenge =
        tpm._Sessions(pw, policy)
        .ActivateCredential(keyToActivate,   // activateHandle (AIK)
                            ekHandle,        // keyHandle      (EK)
                            cred.CredentialBlob,
                            cred.Secret);

    printf("Decrypted challenge: ");
    for (BYTE b : decryptedChallenge)
    {
        printf("%02X ", static_cast<unsigned>(b));
    }
    printf("\n");
    fp.set_tpmchallenge(std::string(decryptedChallenge.begin(), decryptedChallenge.end()));

    tpm.FlushContext(policy);
    tpm.FlushContext(keyToActivate);

    // The derivative signing key would normally now be signed by the server
    // However, we only created a derivative key because the TPM refuses to use the EK otherwise.
    // Instead we discard the signing key.

    return true;
}

constexpr LPCWSTR REG_PATH = L"SOFTWARE\\PocAntiCheat";
constexpr LPCWSTR MACHINE_UUID_NAME = L"MachineUUID";

struct RegKey
{
    HKEY h{};
    ~RegKey()
    {
        if (h)
            RegCloseKey(h);
    }
};

uint8_t* string_as_byte(std::string& str) noexcept {
    return reinterpret_cast<uint8_t*>(&(str)[0]);
}

uint8_t* wstring_as_byte(std::wstring& str) noexcept {
    return reinterpret_cast<uint8_t*>(&(str)[0]);
}

uint64_t current_timestamp() noexcept {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
}

bool registry_trace(Fingerprint &fp) noexcept
{
    ZoneScopedN("Registry");
    RegKey key;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, REG_PATH, 0, nullptr,
                        REG_OPTION_NON_VOLATILE,
                        KEY_READ | KEY_WRITE | KEY_WOW64_64KEY,
                        nullptr, &key.h, nullptr) != ERROR_SUCCESS)
    {
        return false;
    }

    DWORD type{}, size{};

    // Query existing value
    if (RegQueryValueExW(key.h, MACHINE_UUID_NAME, nullptr, &type, nullptr, &size) == ERROR_SUCCESS && type == REG_SZ && size > 0)
    {
        std::wstring value(size / sizeof(wchar_t), L'\0');
        if (RegQueryValueExW(key.h, MACHINE_UUID_NAME, nullptr, nullptr, wstring_as_byte(value), &size) != ERROR_SUCCESS)
            return false;

        // Convert wide‑string to narrow for parsing
        std::string ascii{value.begin(), value.end()};
        fp.set_registrykey(std::string(16, '\0'));
        if (uuidv7_from_string(ascii.c_str(), string_as_byte(*fp.mutable_registrykey())) != 0)
            return false;
        return true;
    }

    // Generate new UUIDv7
    std::array<uint8_t, 10> randBytes;
    if (BCryptGenRandom(nullptr, randBytes.data(), static_cast<ULONG>(randBytes.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        return false;

    fp.set_registrykey(std::string(16, '\0'));
    uuidv7_generate(string_as_byte(*fp.mutable_registrykey()), current_timestamp(), randBytes.data(), nullptr);

    // Convert to string
    std::array<char, 37> uuidStr{};
    uuidv7_to_string(string_as_byte(*fp.mutable_registrykey()), uuidStr.data());
    std::wstring wide(uuidStr.begin(), uuidStr.end());

    return RegSetValueExW(key.h, MACHINE_UUID_NAME, 0, REG_SZ,
                          reinterpret_cast<const BYTE *>(wide.c_str()),
                          static_cast<DWORD>((wide.size() + 1) * sizeof(wchar_t))) == ERROR_SUCCESS;
}


// WMI fingerprint

template <typename T>
class ComPtr {
public:
    ComPtr() : ptr_(nullptr) {}
    explicit ComPtr(T* ptr) : ptr_(ptr) { if (ptr_) ptr_->AddRef(); }
    ComPtr(const ComPtr& other) : ptr_(other.ptr_) { if (ptr_) ptr_->AddRef(); }
    ComPtr(ComPtr&& other) noexcept : ptr_(other.ptr_) { other.ptr_ = nullptr; }
    ~ComPtr() { release(); }

    ComPtr& operator=(T* ptr) {
        release();
        ptr_ = ptr;
        if (ptr_) ptr_->AddRef();
        return *this;
    }

    ComPtr& operator=(const ComPtr& other) {
        if (this != &other) {
            release();
            ptr_ = other.ptr_;
            if (ptr_) ptr_->AddRef();
        }
        return *this;
    }

    ComPtr& operator=(ComPtr&& other) noexcept {
        if (this != &other) {
            release();
            ptr_ = other.ptr_;
            other.ptr_ = nullptr;
        }
        return *this;
    }

    T* get() const { return ptr_; }
    T** operator&() { // Used to pass to functions that output a COM ptr (e.g., CoCreateInstance)
        release();
        return &ptr_;
    }
    T* operator->() const { return ptr_; }

    explicit operator bool() const { return ptr_ != nullptr; }

    void release() {
        if (ptr_) {
            ptr_->Release();
            ptr_ = nullptr;
        }
    }

private:
    T* ptr_;
};

class ComInitializer {
public:
    ComInitializer(DWORD coInitModel = COINIT_MULTITHREADED) 
        : hr_(E_FAIL), comInitializedByThisInstance_(false) {
        hr_ = CoInitializeEx(NULL, coInitModel);
        if (SUCCEEDED(hr_)) {
            comInitializedByThisInstance_ = true;
        } else if (hr_ == RPC_E_CHANGED_MODE) {
            // printf("COM already initialized with a different concurrency model. Proceeding.\n");
        } else {
            printf("ComInitializer: CoInitializeEx failed with HRESULT: 0x%lx\n", hr_);
        }
    }

    ~ComInitializer() {
        if (comInitializedByThisInstance_) {
            CoUninitialize();
        }
    }

    HRESULT getHResult() const { return hr_; }
    bool isSuccess() const { 
        return SUCCEEDED(hr_) || hr_ == RPC_E_CHANGED_MODE;
    }

private:
    HRESULT hr_;
    bool comInitializedByThisInstance_;

    ComInitializer(const ComInitializer&) = delete;
    ComInitializer& operator=(const ComInitializer&) = delete;
};

class VariantGuard {
public:
    VariantGuard() { VariantInit(&var_); }
    ~VariantGuard() { VariantClear(&var_); }

    VARIANT* operator&() { return &var_; }
    VARIANT& get() { return var_; }

    VARTYPE vt() const { return var_.vt; }
    BSTR bstrVal() const {
        return var_.vt == VT_BSTR ? var_.bstrVal : nullptr; 
    } 
    SAFEARRAY* array() const {
        return (var_.vt & VT_ARRAY) ? V_ARRAY(&var_) : nullptr; 
    }

private:
    VARIANT var_;
    VariantGuard(const VariantGuard&) = delete;
    VariantGuard& operator=(const VariantGuard&) = delete;
};

namespace WmiHelpers {

class SafeArrayDataGuard {
public:
    SafeArrayDataGuard(SAFEARRAY* sa) : sa_(nullptr), pData_(nullptr), hr_(E_FAIL) {
        if (sa) {
            sa_ = sa;
            hr_ = SafeArrayAccessData(sa_, &pData_);
        }
    }
    ~SafeArrayDataGuard() {
        // Only unaccess if sa_ was valid and access was successful
        if (sa_ && SUCCEEDED(hr_)) {
            SafeArrayUnaccessData(sa_);
        }
    }
    bool isSuccess() const { return SUCCEEDED(hr_); }
    void* getData() const { return pData_; }

private:
    SAFEARRAY* sa_;
    void* pData_;
    HRESULT hr_;
    SafeArrayDataGuard(const SafeArrayDataGuard&) = delete;
    SafeArrayDataGuard& operator=(const SafeArrayDataGuard&) = delete;
};

bool GetStringProperty(IWbemClassObject* obj, const wchar_t* propName, std::wstring& value) {
    if (!obj || !propName) return false;
    VariantGuard var;
    HRESULT hr = obj->Get(propName, 0, &var.get(), NULL, NULL);
    if (SUCCEEDED(hr) && var.vt() == VT_BSTR && var.bstrVal() != NULL) {
        value = var.bstrVal();
        return true;
    }
    // wprintf(L"GetStringProperty: Failed to get '%s' or not a BSTR. HR=0x%lx, VT=%d\n", propName, hr, var.vt());
    return false;
}

bool GetLongArrayProperty(IWbemClassObject* obj, const wchar_t* propName, std::vector<LONG>& values) {
    if (!obj || !propName) return false;
    VariantGuard var;
    HRESULT hr = obj->Get(propName, 0, &var.get(), NULL, NULL);
    if (SUCCEEDED(hr) && var.vt() == (VT_ARRAY | VT_I4)) { // Check for array of LONGs (VT_I4)
        SAFEARRAY* pSa = var.array();
        if (!pSa) return false;

        SafeArrayDataGuard dataGuard(pSa);
        if (!dataGuard.isSuccess()) return false;

        LONG* pData = static_cast<LONG*>(dataGuard.getData());
        if (!pData) return false;

        LONG lBound = 0, uBound = 0;
        if (FAILED(SafeArrayGetLBound(pSa, 1, &lBound)) || FAILED(SafeArrayGetUBound(pSa, 1, &uBound))) {
            return false;
        }

        size_t count = (uBound - lBound + 1);
        if (count > 0) {
            values.assign(pData + lBound, pData + uBound + 1);
        } else {
            values.clear();
        }
        return true;
    }
    // wprintf(L"GetLongArrayProperty: Failed for '%s'. HR=0x%lx, VT=%d\n", propName, hr, var.vt());
    return false;
}

bool GetUint8ArrayProperty(IWbemClassObject* obj, const wchar_t* propName, std::vector<BYTE>& values) {
    if (!obj || !propName) return false;
    VariantGuard var;
    HRESULT hr = obj->Get(propName, 0, &var.get(), NULL, NULL);
     if (SUCCEEDED(hr) && (var.vt() == (VT_ARRAY | VT_UI1))) { // Check for array of BYTEs (VT_UI1)
        SAFEARRAY* pSa = var.array();
        if (!pSa) return false;

        SafeArrayDataGuard dataGuard(pSa);
        if (!dataGuard.isSuccess()) return false;

        BYTE* pData = static_cast<BYTE*>(dataGuard.getData());
        if (!pData) return false;

        LONG lBound = 0, uBound = 0;
        if (FAILED(SafeArrayGetLBound(pSa, 1, &lBound)) || FAILED(SafeArrayGetUBound(pSa, 1, &uBound))) {
            return false;
        }

        size_t count = (uBound - lBound + 1);
        if (count > 0) {
            values.assign(pData + lBound, pData + uBound + 1);
        } else {
            values.clear();
        }
        return true;
    }
    // wprintf(L"GetUint8ArrayProperty: Failed for '%s'. HR=0x%lx, VT=%d\n", propName, hr, var.vt());
    return false;
}

}

class WmiSession {
public:
    WmiSession() = default;

    // Connects to the specified WMI namespace
    bool connect(const std::wstring& wmiNamespace) {
        // CoInitializeSecurity: Best effort. Called once per process with specific parameters.
        // If already called (even with different params), RPC_E_TOO_LATE is returned, which is usually fine.
        HRESULT hr = CoInitializeSecurity(NULL, -1, NULL, NULL,
                                          RPC_C_AUTHN_LEVEL_DEFAULT, 
                                          RPC_C_IMP_LEVEL_IMPERSONATE,
                                          NULL, EOAC_NONE, 0);
        if (FAILED(hr) && hr != RPC_E_TOO_LATE) {
            printf("WmiSession: CoInitializeSecurity failed: 0x%lx\n", hr);
            return false;
        }

        hr = CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
                              IID_PPV_ARGS(&pLocator_));
        if (FAILED(hr)) {
            printf("WmiSession: CoCreateInstance for WbemLocator failed: 0x%lx\n", hr);
            return false;
        }

        hr = pLocator_->ConnectServer(_bstr_t(wmiNamespace.c_str()), NULL, NULL, NULL,
                                     WBEM_FLAG_CONNECT_USE_MAX_WAIT, NULL, NULL, &pService_);
        if (FAILED(hr)) {
            printf("WmiSession: ConnectServer to namespace '%ls' failed: 0x%lx\n", wmiNamespace.c_str(), hr);
            return false;
        }

        // Set security levels on the WMI proxy
        hr = CoSetProxyBlanket(
            pService_.get(),
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            NULL,
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL,
            EOAC_NONE
        );
        if (FAILED(hr)) {
            printf("WmiSession: CoSetProxyBlanket failed: 0x%lx\n", hr);
            return false; 
        }
        return true;
    }

    ~WmiSession() = default;

    // Defines the signature for functions that process WMI query results.
    using WmiObjectProcessor = std::function<void(ComPtr<IWbemClassObject>&, Fingerprint&)>;

    // Executes a WQL query and processes each resulting WMI object using the provided processor.
    bool executeQuery(const std::wstring& wqlQuery, Fingerprint& fp, WmiObjectProcessor processor) {
        if (!pService_) {
            printf("WmiSession: Not connected. Call connect() first.\n");
            return false;
        }

        ComPtr<IEnumWbemClassObject> enumerator;
        HRESULT hr = pService_->ExecQuery(
            _bstr_t(L"WQL"), // Query language
            _bstr_t(wqlQuery.c_str()), // Query string
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, // Flags
            NULL, // Context
            &enumerator // Receives the enumerator
        );

        if (FAILED(hr)) {
            printf("WmiSession: ExecQuery for '%ls' failed: 0x%lx\n", wqlQuery.c_str(), hr);
            return false;
        }

        ComPtr<IWbemClassObject> clsObj;
        ULONG itemsReturned = 0;
        // Loop through the query results
        while (enumerator) {
            // Fetch one object at a time.
            hr = enumerator->Next(WBEM_INFINITE, 1, &clsObj, &itemsReturned);

            if (FAILED(hr)) {
                 printf("WmiSession: enumerator->Next failed: 0x%lx\n", hr);
                 break;
            }
            if (itemsReturned == 0 || hr == WBEM_S_FALSE) {
                break;
            }

            processor(clsObj, fp); // Call the custom processor for the current object
            clsObj.release();
        }

        if (FAILED(hr) && hr != WBEM_S_FALSE) {
            // An actual error occurred during enumeration.
            return false;
        }
        return true;
    }

private:
    ComPtr<IWbemLocator> pLocator_;
    ComPtr<IWbemServices> pService_;

    WmiSession(const WmiSession&) = delete;
    WmiSession& operator=(const WmiSession&) = delete;
};

namespace WmiProcessors {

void ProcessMonitorInfo(ComPtr<IWbemClassObject>& clsObj, Fingerprint& fp) {
    // 16 bytes ProductCodeID + 16 bytes SerialNumberID
    std::string monitorIdCombined(32, '\0');
    bool productCodeSet = false;
    bool serialNumberSet = false;

    std::vector<LONG> productCodeID_data;
    if (WmiHelpers::GetLongArrayProperty(clsObj.get(), L"ProductCodeID", productCodeID_data)) {
        if (productCodeID_data.size() == 16) {
            for (size_t i = 0; i < 16; ++i) {
                monitorIdCombined[i] = static_cast<char>(productCodeID_data[i] & 0xFF);
            }
            productCodeSet = true;
        } else {
            // wprintf(L"  ProductCodeID: Array size is %zu, expected 16.\n", productCodeID_data.size());
        }
    }

    std::vector<LONG> serialNumberID_data;
    if (WmiHelpers::GetLongArrayProperty(clsObj.get(), L"SerialNumberID", serialNumberID_data)) {
        if (serialNumberID_data.size() == 16) {
            for (size_t i = 0; i < 16; ++i) {
                monitorIdCombined[i + 16] = static_cast<char>(serialNumberID_data[i] & 0xFF);
            }
            serialNumberSet = true;
        } else {
            // wprintf(L"  SerialNumberID: Array size is %zu, expected 16.\n", serialNumberID_data.size());
        }
    }
    
    // Only add if at least one of the IDs was successfully retrieved and has the correct size
    if (productCodeSet || serialNumberSet) {
        fp.add_monitorids(monitorIdCombined);
    }
}

void ProcessBiosInfo(ComPtr<IWbemClassObject>& clsObj, Fingerprint& fp) {
    std::wstring serialNumber;
    if (WmiHelpers::GetStringProperty(clsObj.get(), L"SerialNumber", serialNumber)) {
        if (!serialNumber.empty()) {
            std::string sn_str(serialNumber.begin(), serialNumber.end());
            // printf("BIOS SerialNumber: %s\n", sn_str.c_str());
            fp.set_biosserial(sn_str);
        }
    }
}

void ProcessDiskDriveInfo(ComPtr<IWbemClassObject>& clsObj, Fingerprint& fp) {
    std::wstring serialNumber;
    // Fetches the SerialNumber property from Win32_DiskDrive
    if (WmiHelpers::GetStringProperty(clsObj.get(), L"SerialNumber", serialNumber)) {
        if (!serialNumber.empty()) {
            size_t first = serialNumber.find_first_not_of(L" \t\n\r\f\v");
            if (std::wstring::npos == first) {
                return;
            }
            size_t last = serialNumber.find_last_not_of(L" \t\n\r\f\v");
            std::wstring trimmedSerialNumber = serialNumber.substr(first, (last - first + 1));

            if (!trimmedSerialNumber.empty()) {
                wprintf(L"Disk SerialNumber: %s\n", trimmedSerialNumber.c_str()); // Optional logging
                std::string sn_str(trimmedSerialNumber.begin(), trimmedSerialNumber.end());
                fp.add_diskserials(sn_str);
            }
        }
    }
}

void ProcessLogicalDiskInfo(ComPtr<IWbemClassObject>& clsObj, Fingerprint& fp) {
    std::wstring volumeSerialNumber;
    // Fetches the VolumeSerialNumber property from Win32_LogicalDisk
    if (WmiHelpers::GetStringProperty(clsObj.get(), L"VolumeSerialNumber", volumeSerialNumber)) {
        if (!volumeSerialNumber.empty()) {
            // VolumeSerialNumber is typically a hex string like "E0A33C1B"
            wprintf(L"Volume SerialNumber: %s\n", volumeSerialNumber.c_str()); // Optional logging
            std::string vsn_str(volumeSerialNumber.begin(), volumeSerialNumber.end());
            fp.add_volumeserials(vsn_str);
        }
    }
}

void ProcessProcessorInfo(ComPtr<IWbemClassObject>& clsObj, Fingerprint& fp) {
    std::wstring processorId;
    // Fetches the ProcessorId property from Win32_Processor
    if (WmiHelpers::GetStringProperty(clsObj.get(), L"ProcessorId", processorId)) {
        if (!processorId.empty()) {
            wprintf(L"Processor ID: %s\n", processorId.c_str()); // Optional logging
            std::string pid_str(processorId.begin(), processorId.end());
            fp.set_cpuserial(pid_str);
        }
    }
}

}

bool wmi_fingerprint(Fingerprint &fp)
{
    ZoneScopedN("WMI");
    // Initialize COM for the current thread
    ComInitializer comInitGuard(COINIT_MULTITHREADED);
    if (!comInitGuard.isSuccess()) {
        // If ComInitializer failed (and it wasn't RPC_E_CHANGED_MODE), WMI calls will likely fail.
        printf("wmi_fingerprint: Failed to initialize COM (HRESULT: 0x%lx). Aborting WMI operations.\n", comInitGuard.getHResult());
        return false;
    }

    bool overallSuccess = true;

    // Create a root WMI session
    WmiSession sessionRootWmi;
    if (!sessionRootWmi.connect(L"root\\wmi")) {
        printf("wmi_fingerprint: Failed to connect to WMI namespace root\\wmi.\n");
        // Depending on requirements, this could be a fatal error for the whole function
        return false; 
    }

    // Execute queries using the session

    // Monitor IDs
    if (!sessionRootWmi.executeQuery(L"SELECT * FROM WmiMonitorID", fp, WmiProcessors::ProcessMonitorInfo)) {
        printf("wmi_fingerprint: Failed to query/process WmiMonitorID.\n");
        overallSuccess = false;
    }

    // Create a cimv2 WMI session
    WmiSession sessionRootCimV2;
    if (!sessionRootCimV2.connect(L"root\\cimv2")) {
        printf("wmi_fingerprint: Failed to connect to WMI namespace root\\cimv2.\n");
        overallSuccess = false; 
    } else {
        // BIOS serial number
        if (!sessionRootCimV2.executeQuery(L"SELECT SerialNumber FROM Win32_BaseBoard", fp, WmiProcessors::ProcessBiosInfo)) {
           printf("wmi_fingerprint: Failed to query/process Win32_BaseBoard.\n");
           overallSuccess = false;
        }

        // Disk Drive Serial Numbers
        if (!sessionRootCimV2.executeQuery(L"SELECT SerialNumber FROM Win32_DiskDrive", fp, WmiProcessors::ProcessDiskDriveInfo)) {
           printf("wmi_fingerprint: Failed to query/process Win32_DiskDrive.\n");
           overallSuccess = false;
        }

        // Logical Disk Volume Serial Numbers
        // Retrieves volume serials for all logical disks (C:, D:, etc.)
        if (!sessionRootCimV2.executeQuery(L"SELECT VolumeSerialNumber FROM Win32_LogicalDisk", fp, WmiProcessors::ProcessLogicalDiskInfo)) {
           printf("wmi_fingerprint: Failed to query/process Win32_LogicalDisk.\n");
           overallSuccess = false;
        }

        // CPU Processor ID
        if (!sessionRootCimV2.executeQuery(L"SELECT ProcessorId FROM Win32_Processor", fp, WmiProcessors::ProcessProcessorInfo)) {
           printf("wmi_fingerprint: Failed to query/process Win32_Processor.\n");
           overallSuccess = false;
        }
    }

    return overallSuccess;
}

static inline bool arp_row_is_valid(const MIB_IPNET_ROW2& row) noexcept
{
    return row.PhysicalAddressLength == 6 &&
            (row.PhysicalAddress[0] & 1) == 0 &&
            (row.State != NlnsUnreachable && row.State != NlnsIncomplete);
}

static inline std::array<uint8_t, 6> arp_row_to_mac(const MIB_IPNET_ROW2& row) noexcept
{
    std::array<uint8_t, 6> mac{};
    memcpy(mac.data(), row.PhysicalAddress, 6);
    return mac;
}

static inline bool mac_equal(const std::array<uint8_t, 6>& a,
                             const std::array<uint8_t, 6>& b) noexcept
{
    return memcmp(a.data(), b.data(), a.size()) == 0;
}

bool arp_fingerprint(Fingerprint& fp, std::size_t n) noexcept
{
    ZoneScopedN("ARP");
    // Find adapter used to connect to internet (filters out things like virtual adapters)
    SOCKADDR_INET dst{};
    dst.si_family = AF_INET;
    dst.Ipv4.sin_addr.s_addr = htonl(0x08080808); // Use 8.8.8.8 as well known public address
    DWORD bestIfIdx = 0;
    if (GetBestInterface(dst.Ipv4.sin_addr.s_addr, &bestIfIdx) != NO_ERROR) {
        return false;
    }

    // Find gateway IP
    uint32_t gatewayIp = 0;
    MIB_IPFORWARD_ROW2 bestRoute{};
    SOCKADDR_INET bestSourceAddress;
    if (GetBestRoute2(nullptr, bestIfIdx, nullptr, &dst, 0, &bestRoute, &bestSourceAddress) == NO_ERROR) {
        gatewayIp = ntohl(bestRoute.NextHop.Ipv4.sin_addr.s_addr);
    }

    // Get table of cached local network devices
    PMIB_IPNET_TABLE2 tbl = nullptr;
    if (GetIpNetTable2(AF_UNSPEC, &tbl) != NO_ERROR || !tbl) {
        return false;
    }

    // Gather MACs
    std::vector<std::array<uint8_t, 6>> macs;
    macs.reserve(tbl->NumEntries);

    std::array<uint8_t, 6> gatewayMac{};
    bool haveGatewayMac = false;

    for (DWORD i = 0; i < tbl->NumEntries; ++i)
    {
        const auto& row = tbl->Table[i];
        if (!arp_row_is_valid(row))
            continue;

        auto mac = arp_row_to_mac(row);

        // If this row matches the gateway IP, remember the MAC
        if (!haveGatewayMac && row.Address.si_family == AF_INET)
        {
            uint32_t ip = ntohl(row.Address.Ipv4.sin_addr.s_addr);
            if (ip == gatewayIp)
            {
                printf("Found gateway MAC\n");
                gatewayMac      = mac;
                haveGatewayMac  = true;
            }
            continue;
        }

        // Add mac address if we haven't seen it yet
        if (std::find_if(macs.begin(), macs.end(), [&mac](const auto& m) { return mac_equal(m, mac); }) == macs.end()) {
            macs.push_back(mac);
        }
    }
    FreeMibTable(tbl);

    // By sorting we have a higher change of repeatedly finding the same devices in the network
    std::sort(macs.begin(), macs.end());

    // Add the mac gateway as the first element, so it will always be included
    if (haveGatewayMac) {
        macs.insert(macs.begin(), gatewayMac);
    }

    if (macs.empty()) {
        return false;
    }

    if (macs.size() > n)
    {
        macs.resize(n);
    }

    // Add mac addresses to fingerprint
    for (const auto& m : macs) {
        fp.add_macaddresses(std::string(m.begin(), m.end()));
    }

    return true;
}

bool kernel_fingerprint(Fingerprint &fp) {
    ZoneScopedN("Kernel");
    HANDLE h = CreateFile(
        R"(\\.\AnticheatPoc)",
        GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, 0, nullptr);

    if (h == INVALID_HANDLE_VALUE) {
        std::cout << "Failed to open driver: " << GetLastError() << "\n";
        return false;
    }

    FINGERPRINT_KERNEL fp_kernel = {};
    DWORD bytes = 0;

    BOOL ok = DeviceIoControl(
        h,
        IOCTL_GET_FINGERPRINT,
        nullptr, 0,
        &fp_kernel, sizeof(fp_kernel),
        &bytes, nullptr);

    if (!ok) {
        std::cerr << "IOCTL failed: " << GetLastError() << "\n";
        CloseHandle(h);
        return 1;
    }

    if (bytes < sizeof(fp_kernel)) {
        std::cerr << "Driver asked for buffer size " << bytes << "\n";
        CloseHandle(h);
        return 1;
    }
    fp.set_kernelhooks(fp_kernel.kernelHooks != 0);
    fp.set_testsigning(fp_kernel.testSigning != 0);
    fp.set_kernelbiosserial(string(fp_kernel.biosSerial));

    std::cout
        << "kernelHooks = " << std::boolalpha << (fp_kernel.kernelHooks != 0) << "\n"
        << "testSigning = " << std::boolalpha << (fp_kernel.testSigning != 0) << "\n"
        << "kernelBiosSerial  = " << fp_kernel.biosSerial << "\n";

    CloseHandle(h);
}
