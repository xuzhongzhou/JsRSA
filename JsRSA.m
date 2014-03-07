//
//  JsRSA.m
//  RSADemo
//
//  Created by Jackson on 14-3-6.
//  Copyright (c) 2014年 Jackson. All rights reserved.
//

#import "JsRSA.h"

#define MAX_ENCRYPT_BLOCK 117
#define MAX_DECRYPT_BLOCK 128

@implementation JsRSA

- (instancetype)init {
    self = [super init];
    if (self) {
        _rsa = RSA_new();
        assert(_rsa != NULL);
    }
    return self;
}

- (BOOL)importRSAKeyWithType:(KeyType)type {
    FILE *file;
    NSString *keyName = (type == KeyTypePublic ? @"public_key" : @"private_key");
    NSString *keyPath = [[NSBundle mainBundle] pathForResource:keyName ofType:@"pem"];
    file = fopen([keyPath UTF8String], "rb");
    if (NULL != file) {
        if (type == KeyTypePublic) {
            PEM_read_RSA_PUBKEY(file, &_rsa, NULL, NULL);
            assert(_rsa != NULL);
        } else {
            PEM_read_RSAPrivateKey(file, &_rsa, NULL, NULL);
            assert(_rsa != NULL);
        }
        fclose(file);
        return ((_rsa != NULL) ? YES : NO);
    }
    return NO;
}

- (NSData *)encryptRSAKeyWithType:(KeyType)keyType paddingType:(RSA_PADDING_TYPE)padding data:(NSData *)data {
    if (data && [data length]) {
        NSMutableData *encryptedData = [NSMutableData dataWithCapacity:0];
        int flen_total = [data length];
        while (flen_total) {
            int flen = MAX_ENCRYPT_BLOCK;
            if (flen_total <= flen) {
                flen = flen_total;
            }
            unsigned char from[flen];
            bzero(from, sizeof(from));
            memcpy(from, [[data subdataWithRange:NSMakeRange([data length] - flen_total, flen)] bytes], flen);
            unsigned char to[128];
            bzero(to, sizeof(to));
            int len = [self encryptRSAKeyWithType:keyType :from :flen :to :padding];
            if (len > 0) {
                [encryptedData appendBytes:to length:len];
            }
            flen_total -= flen;
        }
        return encryptedData;
    }
    return nil;
}

- (NSData *)encryptRSAKeyWithType:(KeyType)keyType paddingType:(RSA_PADDING_TYPE)padding plainText:(NSString *)text usingEncoding:(NSStringEncoding)encode {
    if (text && [text length]) {
        return [self encryptRSAKeyWithType:keyType paddingType:padding data:[text dataUsingEncoding:encode]];
    }
    return nil;
}

- (NSString *)decryptRSAKeyWithType:(KeyType)keyType paddingType:(RSA_PADDING_TYPE)padding plainTextData:(NSData *)data usingEncoding:(NSStringEncoding)encode {
    if (data && [data length]) {
        NSData *decryptData = [self decryptRSAKeyWithType:keyType paddingType:padding encryptedData:data];
        return [[NSString alloc] initWithData:decryptData encoding:encode];
    }
    return nil;
}

- (NSData *)decryptRSAKeyWithType:(KeyType)keyType paddingType:(RSA_PADDING_TYPE)padding encryptedData:(NSData *)data {
    if (data && [data length]) {
        NSMutableData *decryptedData = [NSMutableData dataWithCapacity:0];
        int flen_total = [data length];
        while (flen_total) {
            int flen = MAX_DECRYPT_BLOCK;
            if (flen_total <= flen) {
                flen = flen_total;
            }
            unsigned char from[flen];
            bzero(from, sizeof(from));
            memcpy(from, [[data subdataWithRange:NSMakeRange([data length] - flen_total, flen)] bytes], flen);
            unsigned char to[128];
            bzero(to, sizeof(to));
            int len = [self decryptRSAKeyWithType:keyType :from :flen :to :padding];
            if (len > 0) {
                [decryptedData appendBytes:to length:len];
            }
            flen_total -= flen;
        }
        return decryptedData;
    }
    return nil;
}

#pragma mark - Base

- (int)encryptRSAKeyWithType:(KeyType)keyType :(const unsigned char *)from :(int)flen :(unsigned char *)to :(RSA_PADDING_TYPE)padding {
    if (from != NULL && to != NULL) {
        int status = 1;
        if (!status) {
            return -1;
        }
        switch (keyType) {
            case KeyTypePrivate: {
                //start encrypt
                status =  RSA_private_encrypt(flen, from,to, _rsa,  padding);
            }
                break;
            default:{
                //start encrypt
                status =  RSA_public_encrypt(flen,from,to, _rsa,  padding);
            }
                break;
        }
        return status;
    }
    return -1;
}

- (int)decryptRSAKeyWithType:(KeyType)keyType :(const unsigned char *)from :(int)flen :(unsigned char *)to :(RSA_PADDING_TYPE)padding {
    if (from != NULL && to != NULL) {
        int status = RSA_check_key(_rsa);
        if (!status) {
            return -1;
        }
        switch (keyType) {
            case KeyTypePrivate:{
                //start encrypt
                status =  RSA_private_decrypt(flen, from, to, _rsa,  padding);
            }
                break;
            default:{
                //start encrypt
                status =  RSA_public_decrypt(flen, from, to, _rsa,  padding);
            }
                break;
        }
        return status;
    }
    return -1;
}

- (void)dealloc {
    RSA_free(_rsa);
}

@end
