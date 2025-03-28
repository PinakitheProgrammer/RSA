#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>

int main() {
    int bits = 4096;
    unsigned long e = RSA_F4;
    RSA *rsa = NULL;
    BIGNUM *bne = NULL;
    FILE *private_key_file = NULL;
    FILE *public_key_file = NULL;

    bne = BN_new();
    BN_set_word(bne, e);

    rsa = RSA_new();
    RSA_generate_key_ex(rsa, bits, bne, NULL);

    private_key_file = fopen("private_key.pem", "w");
    PEM_write_RSAPrivateKey(private_key_file, rsa, NULL, NULL, 0, NULL, NULL);
    fclose(private_key_file);

    public_key_file = fopen("public_key.pem", "w");
    PEM_write_RSAPublicKey(public_key_file, rsa);
    fclose(public_key_file);

    RSA_free(rsa);
    BN_free(bne);

    return 0;
}
