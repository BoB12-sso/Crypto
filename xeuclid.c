#include <stdio.h>
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM * a) 
{ 
	/* Use BN_bn2hex(a) for hex string * Use BN_bn2dec(a) for decimal string */ 
	char * number_str = BN_bn2hex(a);
	printf("%s %s\n", msg, number_str); 
	OPENSSL_free(number_str); 
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

int main (int argc, char *argv[])
{
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    
    if(argc != 3){
        printf("usage: xeuclid num1 num2");
        return -1;
    }

    BN_dec2bn(&a, argv[1]);
    BN_dec2bn(&b, argv[2]);
    gcd = XEuclid(x,y,a,b);


    printBN("(a,b) = ", gcd);
    printBN("a = ", a);
    printBN("b = ", b);
    printBN("x = ", x);
    printBN("y = ", y);
    printf("%s*(%s) + %s*(%s) = %s\n",BN_bn2dec(a),BN_bn2dec(x),BN_bn2dec(b),BN_bn2dec(y),BN_bn2dec(gcd));

    if(a != NULL) BN_free(a);
    if(b != NULL) BN_free(b);
    if(x != NULL) BN_free(x);
    if(y != NULL) BN_free(y);
    if(gcd != NULL) BN_free(gcd);

    return 0;
}

