#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <iterator>
#include <memory>
#include <cstring>

// RAII wrapper for EC_KEY to handle automatic memory management
struct ECKeyDeleter {
    void operator()(EC_KEY* p) const { EC_KEY_free(p); }
};
using UniqueECKey = std::unique_ptr<EC_KEY, ECKeyDeleter>;

class EncryptionManager {
public:
    UniqueECKey generate_key_pair() {
        UniqueECKey eckey(EC_KEY_new_by_curve_name(NID_secp256k1));
        if (!eckey || !EC_KEY_generate_key(eckey.get())) {
            throw std::runtime_error("Error generating EC key");
        }
        return eckey;
    }

    void save_private_key(const std::string& filename, const UniqueECKey& ec_key) {
        BIO* out = BIO_new_file(filename.c_str(), "w");
        if (!out || !PEM_write_bio_ECPrivateKey(out, ec_key.get(), EVP_aes_256_cbc(), nullptr, 0, nullptr, nullptr)) {
            std::cerr << "Error writing private key to file" << std::endl;
        }
        BIO_free(out);
    }

    void save_public_key(const std::string& filename, const UniqueECKey& ec_key) {
        BIO* out = BIO_new_file(filename.c_str(), "w");
        if (!out || !PEM_write_bio_EC_PUBKEY(out, ec_key.get())) {
            std::cerr << "Error writing public key to file" << std::endl;
        }
        BIO_free(out);
    }

    UniqueECKey load_private_key(const std::string& filename) {
        FILE* file = fopen(filename.c_str(), "rb");
        UniqueECKey ecKey(PEM_read_ECPrivateKey(file, nullptr, nullptr, nullptr));
        fclose(file);
        if (!ecKey) {
            throw std::runtime_error("Error loading private key");
        }
        return ecKey;
    }

    UniqueECKey load_public_key(const std::string& filename) {
        FILE* file = fopen(filename.c_str(), "rb");
        UniqueECKey ecKey(PEM_read_EC_PUBKEY(file, nullptr, nullptr, nullptr));
        fclose(file);
        if (!ecKey) {
            throw std::runtime_error("Error loading public key");
        }
        return ecKey;
    }

    std::vector<uint8_t> derive_shared_secret(EC_KEY* privkey, EC_KEY* pubkey) {
        int field_size = EC_GROUP_get_degree(EC_KEY_get0_group(privkey));
        int secret_len = (field_size + 7) / 8;
        std::vector<uint8_t> shared_secret(secret_len);

        int ret = ECDH_compute_key(shared_secret.data(), secret_len, EC_KEY_get0_public_key(pubkey), privkey, nullptr);
        if (ret <= 0) {
            throw std::runtime_error("Error deriving shared secret");
        }

        shared_secret.resize(ret);
        return shared_secret;
    }

    std::vector<uint8_t> encrypt_data(const std::vector<uint8_t>& key, const std::vector<uint8_t>& plaintext) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Error creating cipher context");
        }

        std::vector<uint8_t> iv(EVP_CIPHER_iv_length(EVP_aes_256_cbc()));
        if (!RAND_bytes(iv.data(), iv.size())) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Error generating IV");
        }

        std::vector<uint8_t> ciphertext(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));

        int len;
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1 ||
            EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Error during encryption");
        }

        int ciphertext_len = len;
        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Error during final encryption step");
        }
        ciphertext_len += len;

        ciphertext.resize(ciphertext_len);
        ciphertext.insert(ciphertext.begin(), iv.begin(), iv.end());

        EVP_CIPHER_CTX_free(ctx);

        return ciphertext;
    }

    std::vector<uint8_t> decrypt_data(const std::vector<uint8_t>& key, const std::vector<uint8_t>& ciphertext) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Error creating cipher context");
        }

        std::vector<uint8_t> iv(ciphertext.begin(), ciphertext.begin() + EVP_CIPHER_iv_length(EVP_aes_256_cbc()));

        std::vector<uint8_t> plaintext(ciphertext.size());

        int len;
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1 ||
            EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data() + iv.size(), ciphertext.size() - iv.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Error during decryption");
        }

        int plaintext_len = len;
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Error during final decryption step");
        }
        plaintext_len += len;

        plaintext.resize(plaintext_len);

        EVP_CIPHER_CTX_free(ctx);

        return plaintext;
    }
};

void save_to_file(const std::string& filename, const std::vector<uint8_t>& data) {
    std::ofstream file(filename, std::ios::binary);
    std::copy(data.begin(), data.end(), std::ostreambuf_iterator<char>(file));
}

std::vector<uint8_t> load_from_file(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] << " <mode> <input_file> <output_file> <public_key_file>\n";
        std::cerr << "Mode: encrypt or decrypt\n";
        return 1;
    }

    std::string mode = argv[1];
    std::string input_file = argv[2];
    std::string output_file = argv[3];
    std::string public_key_file = argv[4];

    try {
        OpenSSL_add_all_algorithms();
        ERR_load_BIO_strings();
        ERR_load_crypto_strings();

        EncryptionManager encryptionManager;

        // Load the public key
        UniqueECKey pubKey = encryptionManager.load_public_key(public_key_file);

        // Generate key pair for the sender
        UniqueECKey keyPair = encryptionManager.generate_key_pair();
        encryptionManager.save_private_key("private_key.pem", keyPair);

        std::vector<uint8_t> shared_secret = encryptionManager.derive_shared_secret(keyPair.get(), pubKey.get());

        if (mode == "encrypt") {
            // Load plaintext from file
            std::vector<uint8_t> plaintext = load_from_file(input_file);

            // Encrypt data
            std::vector<uint8_t> ciphertext = encryptionManager.encrypt_data(shared_secret, plaintext);
            save_to_file(output_file, ciphertext);
            std::cout << "Encryption completed successfully." << std::endl;
        } else if (mode == "decrypt") {
            // Load ciphertext from file
            std::vector<uint8_t> loadedCiphertext = load_from_file(input_file);

            // Decrypt data
            std::vector<uint8_t> decrypted = encryptionManager.decrypt_data(shared_secret, loadedCiphertext);
            save_to_file(output_file, decrypted);
            std::cout << "Decryption completed successfully." << std::endl;
        } else {
            std::cerr << "Invalid mode. Use 'encrypt' or 'decrypt'." << std::endl;
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception caught: " << e.what() << std::endl;
        ERR_print_errors_fp(stderr);
        return 1;
    }

    return 0;
}
