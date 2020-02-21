// Adam Zió³kowski: Image encryption using RSA alogrithm with GPU approach.
// STB library used at MIT License, license added to project repository.
//
#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include <iostream>
#include <stdlib.h>
#include <time.h>
#define STB_IMAGE_IMPLEMENTATION
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image.h"
#include "stb_image_write.h"


uint64_t Modulus; 
uint64_t PrivateExponent;
uint64_t PublicExponent;

// Kernel uses iterative modular exponentiation algorithm, each one takes single pixel to encrypt or decrypt it
__global__ void ModExpKernel(uint64_t* original, uint64_t* product, uint64_t exponent, uint64_t mod, int* size)
{
	int i = blockIdx.x * blockDim.x + threadIdx.x;
	if(i < *size){
		uint64_t result = 1;      // Initialize result 
		uint64_t x = original[i];
		
	    x = x % mod;  // Checking if x is more than or equal to mod
	  
	    while (exponent > 0) 
	    { 
	        // I multiply x with result if exp is odd, 
	        if (exponent & 1) 
	            result = (result * x) % mod; 
	  
	        // exp must be even now  
	        exponent = exponent >> 1; // exp = exp/2 
	        x = (x*x) % mod;   
	    } 
	    product[i] = result; 
	}
}


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
    uint16_t upper_limit = 65535; //18446744073709551615;
    uint16_t lower_limit = 55000;  //8446744073709551615;


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

    // 6. Output(e, n) as the public key and (d, n) as the private key

    if ((d * e) % Phi == 1) {  // Test to ensure legitimacy of a key komponents
        printf("Git\n");
        Modulus = n;
        PublicExponent = e;
        PrivateExponent = d;
    }
    else {
        GenerateKeyPair();
    }
}


int main()
{
    srand(time(NULL));
    int width, height, bpp;
    uint64_t* encrypted64, * decrypted64;
    uint8_t* encrypted, * decrypted, * original;
    uint8_t* rgb_image = stbi_load("Lenna.png", &width, &height, &bpp, CHANNEL_NUM);
    
    uint64_t* rgb_image64, buff[4];
    int size = (width * height * CHANNEL_NUM);
    int size64 = size / 2;
    rgb_image64 = new uint64_t[size64];

	// Merging 2 8bit pixels into 64bit structure
    for (int i = 0; i < size64; i++) {
        for (int k = 0; k < 2; k++) {
            buff[k] = 0b0;
            buff[k] = rgb_image[i * 2 + k];
            buff[k] = buff[k] << (8 - k * 8);
        }
        rgb_image64[i] = buff[0] | buff[1];

    }

    GenerateKeyPair();

    printf("Klucz publiczny: %I64u, %I64u\nKlucz prywatny: %I64u, %I64u", PublicExponent, Modulus, PrivateExponent, Modulus);
    printf("\nRozpoczynam szyfrowanie\n");

     // Memory allocation for 8 bit structures for holding final results
    encrypted = new uint8_t[size];
    decrypted = new uint8_t[size];
    original = new uint8_t[size];

    // Allocation of 64 bit structures for holding computing results and said computing
    encrypted64 = new uint64_t[size64];
    decrypted64 = new uint64_t[size64];

	// Here I create device variables
	uint64_t* dev_encrypted64, * dev_decrypted64,* dev_rgb_image64;
	int* dev_size64;
	
	// Device memory allocation with data copy
	cudaMalloc((void**)&dev_rgb_image64, size64*sizeof(uint64_t));
	cudaMalloc((void**)&dev_encrypted64, size64*sizeof(uint64_t));
	cudaMalloc((void**)&dev_decrypted64, size64*sizeof(uint64_t));
	cudaMalloc((void**)&dev_size64, sizeof(int));
	cudaMemcpy(dev_rgb_image64, rgb_image64, size64 * sizeof(uint64_t), cudaMemcpyHostToDevice);
	cudaMemcpy(dev_size64, &size64, sizeof(int), cudaMemcpyHostToDevice);
	
	// Kernel launched for encryption and decryption, both have their own result matrix for result storage 
	ModExpKernel<<<1024,1024>>>(dev_rgb_image64, dev_encrypted64, PublicExponent, Modulus, dev_size64);
	ModExpKernel<<<1024,1024>>>(dev_encrypted64, dev_decrypted64, PrivateExponent, Modulus, dev_size64);
	
	// Copying all images to host
	cudaMemcpy(encrypted64, dev_encrypted64, size64 * sizeof(uint64_t), cudaMemcpyDeviceToHost);
	cudaMemcpy(decrypted64, dev_decrypted64, size64 * sizeof(uint64_t), cudaMemcpyDeviceToHost);
	cudaMemcpy(rgb_image64, dev_rgb_image64, size64 * sizeof(uint64_t), cudaMemcpyDeviceToHost);
	
 
    // Sampling merged pixels to 8 bit form with binary mask and bit shift
    for (int i = 0; i < size64; i++) {
        for (int k = 0; k < 2; k++) {
            buff[k] = 255;
            buff[k] = buff[k] << (8 - k * 8);
            decrypted[i * 2 + k] = (uint8_t)((decrypted64[i] & buff[k]) >> (8 - k * 8));
            encrypted[i * 2 + k] = (uint8_t)((encrypted64[i] & buff[k]) >> (8 - k * 8));
            original[i * 2 + k] = (uint8_t)((rgb_image64[i] & buff[k]) >> (8 - k * 8));
        }
    }

    // Writing images to .png files
    stbi_write_png("original.png", width, height, CHANNEL_NUM, original, width * CHANNEL_NUM);
    stbi_write_png("decrypted.png", width, height, CHANNEL_NUM, decrypted, width * CHANNEL_NUM);
    stbi_write_png("encrypted.png", width, height, CHANNEL_NUM, encrypted, width * CHANNEL_NUM);

    // Releasing memory
    delete(rgb_image);
    delete(rgb_image64);
    delete(encrypted);
    delete(encrypted64);
    delete(decrypted);
    delete(decrypted64);
    delete(original);

    return 0;
}


