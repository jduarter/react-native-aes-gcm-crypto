#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(AesGcmCrypto, NSObject)

  RCT_EXTERN_METHOD(decrypt:(NSArray *)cipherText
                    withKey:(NSArray *)key
                    withNonce:(NSArray *)iv
                    withTag:(NSArray *)tag
                    withAuthenticatingData:(NSArray *)authenticatingData
               withResolver:(RCTPromiseResolveBlock)resolve
               withRejecter:(RCTPromiseRejectBlock)reject)
 RCT_EXTERN_METHOD(decryptFile:(NSString *)inputFilePath
                outputFilePath:(NSString *)outputFilePath
                       withKey:(NSString *)key
                            iv:(NSString *)iv
                           tag:(NSString *)tag
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(encrypt:(NSArray *)plainText
                  withKey:(NSArray *)key
                  withNonce:(NSArray *)nonce
                  withAuthenticatingData:(NSArray *)authenticatingData
             withResolver:(RCTPromiseResolveBlock)resolve
             withRejecter:(RCTPromiseRejectBlock)reject)
 RCT_EXTERN_METHOD(encryptFile:(NSString *)inputPath
                outputFilePath:(NSString *)outputFilePath
                       withKey:(NSString *)key
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)

@end

