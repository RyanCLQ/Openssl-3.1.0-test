/*
 * Copyright 2017-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Internal tests for the SM4 module.
 */

#include <string.h>
#include <openssl/opensslconf.h>
#include "testutil.h"
#include <omp.h>

#ifndef OPENSSL_NO_SM4
# include "crypto/sm4.h"
# include "../include/openssl/modes.h"

void sm4_ecb( uint8_t *input, uint8_t *output, int insize, SM4_KEY key){
    uint8_t * out = output;
    uint8_t * in = input;
    while (insize >= 16){
        ossl_sm4_encrypt(in,out,&key);
        insize -= 16;
        in += 16;
        out += 16;   
    }
    if(insize > 0){
        for (size_t i = 0; i < insize; i++)
        {
            out[i] = in[i];    
        }
    }
}

void sm4_cbc( uint8_t *input, uint8_t *output, int insize, unsigned char* iv, SM4_KEY key){
    CRYPTO_cbc128_encrypt(input, output, insize, &key, iv, (block128_f)ossl_sm4_encrypt);
}

void sm4_gcm_init(GCM128_CONTEXT* gcm_ctx, unsigned char* iv, size_t ivlen, unsigned char* aad, size_t aadlen){
	CRYPTO_gcm128_setiv(gcm_ctx, iv, ivlen);
	CRYPTO_gcm128_aad(gcm_ctx, aad, aadlen);
}

void sm4_gcm_enc(GCM128_CONTEXT* gcm_ctx, uint8_t* input, size_t insize, uint8_t* output){
    CRYPTO_gcm128_encrypt(gcm_ctx, input, output, insize);
}

void sm4_ctr( uint8_t *input, uint8_t *output, int insize, unsigned char* iv, unsigned char* ecount_buf, unsigned int* num, SM4_KEY key){
    CRYPTO_ctr128_encrypt(input, output, insize, &key, iv, ecount_buf, num, (block128_f)ossl_sm4_encrypt); 
}

static int test_sm4(void)
{
    static const uint8_t k[SM4_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    // static const uint8_t input[SM4_BLOCK_SIZE] = {
    //     0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    //     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    // };

    /*
     * This test vector comes from Example 1 of GB/T 32907-2016,
     * and described in Internet Draft draft-ribose-cfrg-sm4-02.
     */
    static const uint8_t expected[SM4_BLOCK_SIZE] = {
        0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
        0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46
    };

    /*
     * This test vector comes from Example 2 from GB/T 32907-2016,
     * and described in Internet Draft draft-ribose-cfrg-sm4-02.
     * After 1,000,000 iterations.
     */
    static const uint8_t expected_iter[SM4_BLOCK_SIZE] = {
        0x59, 0x52, 0x98, 0xc7, 0xc6, 0xfd, 0x27, 0x1f,
        0x04, 0x02, 0xf8, 0x04, 0xc3, 0x3d, 0x3f, 0x66
    };

    int i;
    SM4_KEY key;
    uint8_t block[SM4_BLOCK_SIZE];

    ossl_sm4_set_key(k, &key);
    //memcpy(block, input, SM4_BLOCK_SIZE);

    ossl_sm4_encrypt(block, block, &key);
    // if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, expected, SM4_BLOCK_SIZE))
    //     return 0;
    unsigned char input[16384]={0};
    unsigned char output[16384]={0};
    unsigned char aad[] = {
            0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x03,0x7f,0xff,0xff,0xfe,0x89,0x2c,0x38,0x00,
            0x00,0x5c,0x36,0x5c,0x36,0x5c,0x36
    };
    unsigned char iv_enc[] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
            0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    unsigned char ecount_buf[16]={0};
    unsigned int num = 0;
    size_t count = 100000;
   
    // 多线程测试模板
    #if 1
        // 依次测试不同线程下的性能 
        for (int thread_num = 1; thread_num <= 16; thread_num*=2) {
            double begin,end;
            int sizes[7] = {1, 4, 16, 64, 256, 512, 1024};
            for(int j = 0; j < 7; j++){
                begin = omp_get_wtime();
                #pragma omp parallel for num_threads(thread_num)
                for(int i = 0; i < count;i++){
                    sm4_ecb(input, output, sizes[j]*16, key);
                }
                end = omp_get_wtime();
                printf("\nsm4-ecb enc %d block_size %d threads: run %d times, total time: %f s, per second run %f tims\n", \
                    sizes[j], thread_num, count*sizes[j], (end-begin), count*sizes[j]/(end-begin));
            }
            // 性能测试
           
        }
    #endif

    #if 1
        // 依次测试不同线程下的性能 
        for (int thread_num = 1; thread_num <= 16; thread_num*=2) {
            double begin,end;
            int sizes[7] = {1, 4, 16, 64, 256, 512, 1024};
            for(int j = 0; j < 7; j++){
                begin = omp_get_wtime();
                #pragma omp parallel for num_threads(thread_num)
                for(int i = 0; i < count;i++){
                    sm4_ctr(input, output, sizes[j]*16, iv_enc, ecount_buf, &num, key);
                }
                end = omp_get_wtime();
                printf("\nsm4-ctr enc %d block_size %d threads: run %d times, total time: %f s, per second run %f tims\n", \
                    sizes[j], thread_num, count*sizes[j], (end-begin), count*sizes[j]/(end-begin));
            }
            // 性能测试
           
        }
    #endif

    #if 1
        // 依次测试不同线程下的性能 
        for (int thread_num = 1; thread_num <= 16; thread_num*=2) {
            double begin,end;
            int sizes[7] = {1, 4, 16, 64, 256, 512, 1024};
            for(int j = 0; j < 7; j++){
                begin = omp_get_wtime();
                #pragma omp parallel for num_threads(thread_num)
                for(int i = 0; i < count;i++){
                    sm4_cbc(input, output, sizes[j]*16, iv_enc, key);
                }
                end = omp_get_wtime();
                printf("\nsm4-cbc enc %d block_size %d threads: run %d times, total time: %f s, per second run %f tims\n", \
                    sizes[j], thread_num, count*sizes[j], (end-begin), count*sizes[j]/(end-begin));
            }
            // 性能测试
        }
    #endif

    #if 1
        GCM128_CONTEXT *ctx = CRYPTO_gcm128_new(&key,(block128_f)ossl_sm4_encrypt);
        sm4_gcm_init(ctx, iv_enc, 16, aad, 23);
        // 依次测试不同线程下的性能 
        for (int thread_num = 1; thread_num <= 16; thread_num*=2) {
            double begin,end;
            int sizes[7] = {1, 4, 16, 64, 256, 512, 1024};
            for(int j = 0; j < 7; j++){
                begin = omp_get_wtime();
                #pragma omp parallel for num_threads(thread_num)
                for(int i = 0; i < count;i++){
                    sm4_gcm_enc(ctx, input, sizes[j]*16, output);
                }
                end = omp_get_wtime();
                printf("\nsm4-gcm enc %d block_size %d threads: run %d times, total time: %f s, per second run %f tims\n", \
                    sizes[j], thread_num, count*sizes[j], (end-begin), count*sizes[j]/(end-begin));
            }
            // 性能测试
        }
    #endif


    // for (i = 0; i != 999999; ++i)
    //     ossl_sm4_encrypt(block, block, &key);

    // if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, expected_iter, SM4_BLOCK_SIZE))
    //     return 0;

    // for (i = 0; i != 1000000; ++i)
    //     ossl_sm4_decrypt(block, block, &key);

    // if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, input, SM4_BLOCK_SIZE))
    //     return 0;

    return 1;
}
#endif

int setup_tests(void)
{
#ifndef OPENSSL_NO_SM4
    // ADD_TEST(test_sm4);
    test_sm4();
#endif
    return 1;
}
