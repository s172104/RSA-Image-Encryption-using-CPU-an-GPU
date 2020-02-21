// RSACPU.cpp : This file contains the 'main' function. Program execution begins and ends there.
// Adam Ziółkowski: Image encryption using RSA alogrithm with CPU approach.
// STB library used at MIT License, license added to project repository.

#include <iostream>
#include <stdlib.h>
#include <time.h>
#define STB_IMAGE_IMPLEMENTATION
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image.h"
#include "stb_image_write.h"

#define CHANNEL_NUM 3
#define INT_BITS 64
#define BIT_SHIFT 2

uint64_t Modulus;
uint64_t PrivateExponent;
uint64_t PublicExponent;


// Test if chosen number is prime   
bool ifPrimary(uint64_t n) {
    bool flag = false;
    if (n != 2 && n % 2 == 0) {
        flag = true;
    }
    else {
        for (uint64_t d = 3; d * d <= n; d++) {
            if (n % d == 0) {
                flag = true;
                break;
            }
        }
    }
    return flag;
}

// Algorithm for finding greatest common divisor used for finding main part of private key
uint64_t ExtendedEuclideanAlgorithm(uint64_t a, uint64_t b, uint64_t* x, uint64_t* y) {

    if (a == 0) {
        *x = 0;
        *y = 1;
        return b;
    }
    uint64_t x1, y1;
    uint64_t gcd = ExtendedEuclideanAlgorithm(b % a, a, &x1, &y1);
    *x = y1 - (b / a) * x1;
    *y = x1;
    return gcd;

}


// Function searching for greatest common divisor
uint64_t GCD(uint64_t x, uint64_t y) {

    uint64_t gcd = NAN;

    for (uint64_t i = 1; i <= x && i <= y; i++) {      // Keep executing loop as long as i is less or equal to one of factors
        if (x % i == 0 && y % i == 0)                  // GCD divides both x and y
            gcd = i;
    }

    return gcd;
}


// Generating two key pairs using RSA key generation algorithm
static void GenerateKeyPair(void) {

    uint64_t p, q, n, d, Phi, gcd, y;
    uint16_t upper_limit = 65535;
    uint16_t lower_limit = 55000;


    // 1. Generate a pair of large, random primes p and q
    do {
        p = lower_limit + (rand() % (upper_limit - lower_limit));
    } while (ifPrimary(p));
    do {
        q = lower_limit + (rand() % (upper_limit - lower_limit));
    } while (ifPrimary(q) || p == q);

    // 2. Compute the modulus n = pq
    n = p * q;

    // 3. Calculate Phi using Euler's totient function
    Phi = (p - 1) * (q - 1);

    // 4. Find e that is relatively prime to Phi
    uint64_t e = 3;

    while (e < Phi) {
        if (GCD(e, Phi) == 1)
            break;
        else
            e += 2;
    }

    // 5. Compute the private exponent d from e, p and q.
    gcd = ExtendedEuclideanAlgorithm(e, Phi, &d, &y);

    // 6. Output(n, e) as the public key and (n, d) as the private key
    if ((d * e) % Phi == 1) {
        printf("Git\n");
        Modulus = n;
        PublicExponent = e;
        PrivateExponent = d;
    }
    else {
        GenerateKeyPair();
    }
}



// Encryption/decryption cipher/restored msg = (msg/cipher ^ e/d) % n
// To deal with large numbers I used multiplication property showed below
// a*b % c = ((a%c)(b%c))%c 
// a^b % c = ((a^(b/2) %c)((a^(b/2) %c))%c
// a^b % c = ((a%c)((a^(b-1) %c))%c
uint64_t modularExponentiation(uint64_t a, uint64_t b, uint64_t mod)
{
    if (a == 0)
        return 0;
    if (b == 0) {
        return 1;
    }
    uint64_t d;
    if (b % 2 == 0) {
        d = modularExponentiation(a, b / 2, mod);
        d = (d * d) % mod;
    }
    else {
        d = ((a % mod) * (modularExponentiation(a, b - 1, mod) %mod)) % mod;
    }
    return ((d + mod) % mod);
}


// Encryption using modular exponentiation followed by left bit shift to scramble image 
void Encrypt(uint64_t* original, uint64_t* encrypted, int size) {


    for (int i = 0; i < size; i++) {
        encrypted[i] = modularExponentiation(original[i], PublicExponent, Modulus);
        encrypted[i] = ((encrypted[i] << BIT_SHIFT) | (encrypted[i] >> (INT_BITS - BIT_SHIFT)));
    }
    printf("End of encryption\n");

}

// Encryption using modular exponentiation after right bit shift to unscramble image 
void Decrypt(uint64_t* encrypted, uint64_t* decrypted, int size) {


    for (int i = 0; i < size; i++) {
        encrypted[i] = ((encrypted[i] >> BIT_SHIFT) | (encrypted[i] << (INT_BITS - BIT_SHIFT)));
        decrypted[i] = modularExponentiation(encrypted[i], PrivateExponent, Modulus);
    }
    printf("End of decryption\n");

}


int main()
{
    srand(time(NULL));
    int width, height, bpp;
    uint64_t* encrypted32, * decrypted32;
    uint8_t* encrypted, * decrypted, * original;
    uint8_t* rgb_image = stbi_load("Lenna.png", &width, &height, &bpp, CHANNEL_NUM);

    uint64_t* rgb_image32, buff[4];
    int size = (width * height * CHANNEL_NUM);
    int img32size = size / 2;
    rgb_image32 = new uint64_t[img32size];

    // Merging 2 8bit pixels into 64bit structure
    for (int i = 0; i < img32size; i++) {
        for (int k = 0; k < 2; k++) {
            buff[k] = 0b0;
            buff[k] = rgb_image[i * 2 + k];
            buff[k] = buff[k] << (8 - k * 8);
        }
        rgb_image32[i] = buff[0] | buff[1];

    }

    GenerateKeyPair();

    printf("Klucz publiczny: %I64u, %I64u\nKlucz prywatny: %I64u, %I64u", PublicExponent, Modulus, PrivateExponent, Modulus);
    printf("\nRozpoczynam szyfrowanie\n");

    // Memory allocation for 8 bit structures for holding final results
    encrypted = new uint8_t[size];
    decrypted = new uint8_t[size];
    original = new uint8_t[size];

    // Allocation of 64 bit structures for holding computing results and said computing
    encrypted32 = new uint64_t[img32size];
    decrypted32 = new uint64_t[img32size];
    Encrypt(rgb_image32, encrypted32, img32size);    // encryption
    Decrypt(encrypted32, decrypted32, img32size);    // decryption

    // Sampling merged pixels to 8 bit form with binary mask and bit shift
    for (int i = 0; i < img32size; i++) {
        for (int k = 0; k < 2; k++) {
            buff[k] = 255;
            buff[k] = buff[k] << (8 - k * 8);
            decrypted[i * 2 + k] = (uint8_t)((decrypted32[i] & buff[k]) >> (8 - k * 8));
            encrypted[i * 2 + k] = (uint8_t)((encrypted32[i] & buff[k]) >> (8 - k * 8));
            original[i * 2 + k] = (uint8_t)((rgb_image32[i] & buff[k]) >> (8 - k * 8));
        }
    }


    // Writing images to .png files
    stbi_write_png("original.png", width, height, CHANNEL_NUM, original, width * CHANNEL_NUM);
    stbi_write_png("decrypted.png", width, height, CHANNEL_NUM, decrypted, width * CHANNEL_NUM);
    stbi_write_png("encrypted.png", width, height, CHANNEL_NUM, encrypted, width * CHANNEL_NUM);

    // Releasing memory
    stbi_image_free(rgb_image);
    stbi_image_free(rgb_image32);
    stbi_image_free(encrypted);
    stbi_image_free(encrypted32);
    stbi_image_free(decrypted);
    stbi_image_free(decrypted32);
    stbi_image_free(original);

    return 0;
}