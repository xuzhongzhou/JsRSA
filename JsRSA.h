//
//  JsRSA.h
//  RSADemo
//
//  Created by Jackson on 14-3-6.
//  Copyright (c) 2014年 Jackson. All rights reserved.
//

#import <Foundation/Foundation.h>
#include "openssl/rsa.h"
#include "openssl/pem.h"

typedef enum { KeyTypePublic, KeyTypePrivate } KeyType;

typedef enum {
  RSA_PADDING_TYPE_NONE = RSA_NO_PADDING,
  RSA_PADDING_TYPE_PKCS1 = RSA_PKCS1_PADDING,
  RSA_PADDING_TYPE_SSLV23 = RSA_SSLV23_PADDING
} RSA_PADDING_TYPE;

@interface JsRSA : NSObject {
  RSA *_rsa;
}

- (BOOL)importRSAKeyWithType:(KeyType)type;
- (NSData *)encryptRSAKeyWithType:(KeyType)keyType paddingType:(RSA_PADDING_TYPE)padding plainText:(NSString *)text usingEncoding:(NSStringEncoding)encode;

@end
