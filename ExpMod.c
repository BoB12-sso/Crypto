#include <stdio.h>
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM *a) {
    char *number_str = BN_bn2dec(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int ExpMod(BIGNUM *r, const BIGNUM *a, const BIGNUM *e, BIGNUM *m) {
    BN_CTX *ctx = BN_CTX_new();

    BN_one(r);

    BIGNUM *base = BN_new();
    BIGNUM *exponent = BN_new();
    BIGNUM *temp = BN_new();

    BN_copy(base, a);
    BN_copy(exponent, e);

    while (!BN_is_zero(exponent)) {
        if (BN_is_odd(exponent)) {
            // r = r * base mod m
            BN_mul(temp, r, base, ctx);
            BN_mod(r, temp, m, ctx);
        }

        // base = base^2 mod m
        BN_sqr(temp, base, ctx);
        BN_mod(base, temp, m, ctx);

        // 지수를 반으로 줄임
        BN_rshift1(exponent, exponent);
    }

    BN_free(base);
    BN_free(exponent);
    BN_free(temp);
    BN_CTX_free(ctx);
    return 1;
}

int main(int argc, char *argv[]) {
    BIGNUM *a = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *m = BN_new();
    BIGNUM *res = BN_new();

    if (argc != 4) {
        printf("usage: exp base exponent modulus\n");
        return -1;
    }

    BN_dec2bn(&a, argv[1]);
    BN_dec2bn(&e, argv[2]);
    BN_dec2bn(&m, argv[3]);
    printBN("a = ", a);
    printBN("e = ", e);
    printBN("m = ", m);

    ExpMod(res, a, e, m);

    printBN("a**e mod m = ", res);

    BN_free(a);
    BN_free(e);
    BN_free(m);
    BN_free(res);

    return 0;
}
