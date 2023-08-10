#include <stdio.h>
#include <openssl/bn.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

typedef struct _b12rsa_st {
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *n;
}BOB12_RSA;

char *p_str = "C485F491D12EA7E6FEB95794E9FE0A819168AAC9D545C9E2AE0C561622F265FEB965754C875E049B19F3F945F2574D57FA6A2FC0A0B99A2328F107DD16ADA2A7";
char *q_str = "F9A91C5F20FBBCCC4114FEBABFE9D6806A52AECDF5C9BAC9E72A07B0AE162B4540C62C52DF8A8181ABCC1A9E982DEB84DE500B27E902CD8FDED6B545C067CE4F";

BOB12_RSA *BOB12_RSA_new();
int BOB12_RSA_free(BOB12_RSA *b12rsa);
int BOB12_RSA_KeyGen(BOB12_RSA *b12rsa, int nBits);
int BOB12_RSA_Enc(BIGNUM *c, BIGNUM *m, BOB12_RSA *b12rsa);
int BOB12_RSA_Dec(BIGNUM *m,BIGNUM *c, BOB12_RSA *b12rsa);
BIGNUM* XEuclid(BIGNUM *x, BIGNUM *y, const BIGNUM *a, const BIGNUM *b);
int ExpMod(BIGNUM *r, const BIGNUM *a, const BIGNUM *e, BIGNUM *m);
int GCD(BIGNUM *result, BIGNUM *a, BIGNUM *b);
void printBN(char *msg, BIGNUM * a);

BOB12_RSA *BOB12_RSA_new() {
    BOB12_RSA *b12rsa = (BOB12_RSA *)malloc(sizeof(BOB12_RSA));
    b12rsa->e = BN_new();
    b12rsa->d = BN_new();
    b12rsa->n = BN_new();
    return b12rsa;
}

int BOB12_RSA_free(BOB12_RSA *b12rsa) {
    BN_free(b12rsa->e);
    BN_free(b12rsa->d);
    BN_free(b12rsa->n);
    free(b12rsa);
    return 1;  // 성공적으로 해제됨
}

int BOB12_RSA_KeyGen(BOB12_RSA *b12rsa, int nBits){
    // RSA 연산에 사용
    BIGNUM *phin, *p, *q, *p_1, *q_1, *one;
    BIGNUM *x, *y, *candidate, *result;

    phin = BN_new();
    p = BN_new();
    q = BN_new();
    p_1 = BN_new();
    q_1 = BN_new();
    one = BN_new();
    candidate = BN_new();
    result = BN_new();
    x = BN_new();
    y = BN_new();   

    // n생성
    BN_hex2bn(&p, p_str);
    BN_hex2bn(&q, q_str);
    BN_mul(b12rsa->n, p, q, BN_CTX_new());

    // phin 생성
    BN_dec2bn(&one, "1");
    BN_sub(p_1, p, one);
    BN_sub(q_1, q, one);
    BN_mul(phin, p_1, q_1, BN_CTX_new());

    // e 선택
    // phin과 서로소인 e 선택
    BN_hex2bn(&result, "00");
    srand(time(NULL));

    while(!BN_is_one(result)){
        // Generate a random number between 2 and 65537
        int randomNumber = rand() % (65537 - 2 + 1) + 2;

        // Convert the random number to a string
        char randomNumberStr[10];  // You can adjust the array size as needed
        snprintf(randomNumberStr, sizeof(randomNumberStr), "%d", randomNumber);

        BN_dec2bn(&candidate, randomNumberStr);
        GCD(result, candidate, phin);
    }
    BN_copy(b12rsa->e, candidate);

    // d 계산
    XEuclid(x,y,b12rsa->e,phin);
    //음수면 phin 더해주기
    if(BN_is_negative(x)){
        BN_add(x, x, phin);
    }
    
    BN_copy(b12rsa->d, x);

    BN_free(phin);
    BN_free(p);
    BN_free(q);
    BN_free(p_1);
    BN_free(q_1);
    BN_free(one);
    BN_free(candidate);
    BN_free(result);

    BN_free(x);
    BN_free(y);
}

int BOB12_RSA_Enc(BIGNUM *c, BIGNUM *m, BOB12_RSA *b12rsa){
    ExpMod(c, m, b12rsa->e, b12rsa->n);
}

int BOB12_RSA_Dec(BIGNUM *m,BIGNUM *c, BOB12_RSA *b12rsa){
    ExpMod(m, c, b12rsa->d, b12rsa->n);
}

BIGNUM *gcd;    
BIGNUM* XEuclid(BIGNUM *x, BIGNUM *y, const BIGNUM *a, const BIGNUM *b) {
    
    BIGNUM *r1, *r2, *s1, *s2, *t1, *t2, *q, *r, *s, *t;

    r1 = BN_dup(a);
    r2 = BN_dup(b);

    s1 = BN_new();
    s2 = BN_new();
    t1 = BN_new();
    t2 = BN_new();

    /*temp value..*/
    q = BN_new();
    r = BN_new();
    s = BN_new();
    t = BN_new();
    
    // Set initial values
    BN_one(s1);
    BN_zero(s2);
    BN_zero(t1);
    BN_one(t2);
    
    while (!BN_is_zero(r2) ) {
        // q = r1 / r2
        // q: 몫, r: 나머지
        BN_div(q, r, r1, r2, BN_CTX_new());
        
        // r1=r2
        // r2=r(나머지)
        BN_copy(r1, r2);
        BN_copy(r2, r);
        
        // s1 = s2
        // s2 = s1-q*s2
        BN_mul(s, q, s2, BN_CTX_new());
        BN_sub(s, s1, s);
        BN_copy(s1, s2);
        BN_copy(s2, s);
        
        // t1 = t2
        // t2 = t1-q*t2
        BN_mul(t, q, t2, BN_CTX_new());
        BN_sub(t, t1, t);
        BN_copy(t1, t2);
        BN_copy(t2, t);
    }
    
    // Set the values of x and y (out parameters)
    BN_copy(x, s1);
    BN_copy(y, t1);

    gcd = BN_new();
    BN_copy(gcd, r1);

    // Free 
    BN_free(r1);
    BN_free(r2);
    BN_free(s1);
    BN_free(s2);
    BN_free(t1);
    BN_free(t2);
    BN_free(q);
    BN_free(r);
    BN_free(s);
    BN_free(t);

    return gcd;
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

int GCD(BIGNUM *result, BIGNUM *a, BIGNUM *b) {
    BN_CTX *ctx = BN_CTX_new();
    
    BIGNUM *temp_a = BN_new();
    BIGNUM *temp_b = BN_new();
    BIGNUM *temp = BN_new();
    
    BN_copy(temp_a, a);
    BN_copy(temp_b, b);
    
    while (!BN_is_zero(temp_b)) {
        BN_copy(temp, temp_b);
        BN_mod(temp_b, temp_a, temp_b, ctx);
        BN_copy(temp_a, temp);
    }
    
    BN_copy(result, temp_a);
    
    BN_free(temp_a);
    BN_free(temp_b);
    BN_free(temp);
    BN_CTX_free(ctx);
}

void printBN(char *msg, BIGNUM * a) 
{ 
	/* Use BN_bn2hex(a) for hex string * Use BN_bn2dec(a) for decimal string */ 
	char * number_str = BN_bn2hex(a);
	printf("%s %s\n", msg, number_str); 
	OPENSSL_free(number_str); 
} 

void PrintUsage()
{
printf("usage: rsa [-k|-e e n plaintext|-d d n ciphertext]\n");
}

int main (int argc, char *argv[])
{
    BOB12_RSA *b12rsa = BOB12_RSA_new();
    BIGNUM *in = BN_new();
    BIGNUM *out = BN_new();

    if(argc == 2){
        if(strncmp(argv[1],"-k",2)){
            PrintUsage();
            return -1;
        }
        BOB12_RSA_KeyGen(b12rsa,1024);
        BN_print_fp(stdout,b12rsa->n);
        printf(" ");
        BN_print_fp(stdout,b12rsa->e);
        printf(" ");
        BN_print_fp(stdout,b12rsa->d);

    }else if(argc == 5){
        if(strncmp(argv[1],"-e",2) && strncmp(argv[1],"-d",2)){
            PrintUsage();
            return -1;
        }
        BN_hex2bn(&b12rsa->n, argv[3]);
        BN_hex2bn(&in, argv[4]);
        if(!strncmp(argv[1],"-e",2)){
            BN_hex2bn(&b12rsa->e, argv[2]);
            BOB12_RSA_Enc(out,in, b12rsa);
        }else if(!strncmp(argv[1],"-d",2)){
            BN_hex2bn(&b12rsa->d, argv[2]);
            BOB12_RSA_Dec(out,in, b12rsa);
        }else{
            PrintUsage();
            return -1;
        }
        BN_print_fp(stdout,out);
    }else{
        PrintUsage();
        return -1;
    }

    if(gcd != NULL) BN_free(gcd);
    if(in != NULL) BN_free(in);
    if(out != NULL) BN_free(out);
    if(b12rsa!= NULL) BOB12_RSA_free(b12rsa);

    return 0;
    }