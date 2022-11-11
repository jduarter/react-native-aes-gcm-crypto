import Foundation
import CryptoKit

enum CryptoError: Error {
    case runtimeError(String)
}

@objc(AesGcmCrypto)
class AesGcmCrypto: NSObject {
    @objc static func requiresMainQueueSetup() -> Bool {
        return false
    }
    
    @objc(decryptBytes:withKey:withNonce:withTag:withAuthenticatingData:error:)
    func decryptBytes(cipherText: [UInt8], key: [UInt8], nonce: [UInt8], tag: [UInt8], authenticatingData: [UInt8]?) throws ->  [UInt8] {
        let ciphertextData = Data(cipherText)

        let sealedBox = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: Data(nonce)),
                                              ciphertext: ciphertextData,
                                              tag: Data(tag))
        
        let decryptedData = try authenticatingData == nil ?
            AES.GCM.open(sealedBox, using: SymmetricKey(data: Data(key))) :
            AES.GCM.open(sealedBox, using: SymmetricKey(data: Data(key)), authenticating: Data(authenticatingData!))

        return Array(decryptedData)
    }
 
    @objc(decrypt:withKey:withNonce:withTag:withAuthenticatingData:withResolver:withRejecter:)
    func decrypt(cipherText: [UInt8], key: [UInt8], nonce: [UInt8], tag: [UInt8], authenticatingData: [UInt8]?, resolve:RCTPromiseResolveBlock, reject:RCTPromiseRejectBlock) -> Void {
        do {
            resolve(try self.decryptBytes(cipherText: cipherText,
                                          key: key,
                                          nonce: nonce,
                                          tag: tag,
                                          authenticatingData: authenticatingData))
        } catch CryptoError.runtimeError(let errorMessage) {
            reject("InvalidArgumentError", errorMessage, nil)
        } catch {
            reject("DecryptionError", "Failed to decrypt", error)
        }
    }
    
    @objc(decryptFile:withOutputFilePath:withKey:withNonce:withTag:withResolver:withRejecter:)
    func decryptFile(inputFilePath: String, outputFilePath: String, key: String, iv: String, tag: String, resolve:RCTPromiseResolveBlock, reject:RCTPromiseRejectBlock) -> Void {
        do {
            let keyData: Data = Data(base64Encoded: key)!
            let file = FileHandle.init(forReadingAtPath: inputFilePath)
            if (file == nil) {
                return reject("IOError", "IOError: Could not open file for reading: \(inputFilePath)", nil)
            }
            let sealedData: Data = file!.readDataToEndOfFile()
            file!.closeFile()

            let decryptedData = Data(try self.decryptBytes(cipherText: Array(sealedData),
                                                           key: Array(keyData),
                                                           nonce: Array(iv.utf8),
                                                           tag: Array(tag.utf8),
                                                           authenticatingData: nil))

            if let wfile = FileHandle.init(forWritingAtPath: outputFilePath) {
                wfile.write(decryptedData)
                wfile.closeFile()
            } else {
                return reject("IOError", "IOError: Could not open file for writing: \(outputFilePath)", nil)
            }

            resolve(true)
        } catch CryptoError.runtimeError(let errorMessage) {
            reject("InvalidArgumentError", errorMessage, nil)
        } catch {
            reject("DecryptionError", "Failed to decrypt", error)
        }
    }
            
    @objc(encryptBytes:withKey:withNonce:withAuthenticatingData:error:)
    func encryptBytes(plainText: [UInt8], key: [UInt8], nonce: [UInt8]?, authenticatingData: [UInt8]?) throws -> [String: [UInt8]] {
        let plainData = Data(plainText)
        let keyObj = SymmetricKey(data: Data(key))
        let nonceObj = nonce != nil ? try AES.GCM.Nonce(data: Data(nonce!)) : AES.GCM.Nonce()

        let sealedBox = try authenticatingData != nil ?
            AES.GCM.seal(plainData,
                using: keyObj,
                nonce: nonceObj,
                authenticating: Data(authenticatingData!)
            )
            :
            AES.GCM.seal(plainData,
                using: keyObj,
                nonce: nonceObj
            )

        let iv = sealedBox.nonce.withUnsafeBytes {
            Data(Array($0))
        }

        return [
            "iv": Array(iv),
            "tag": Array(sealedBox.tag),
            "content": Array(sealedBox.ciphertext)
        ]
    }
    
    @objc(encrypt:withKey:withNonce:withAuthenticatingData:withResolver:withRejecter:)
    func encrypt(plainText: [UInt8], key: [UInt8], nonce: [UInt8]?, authenticatingData: [UInt8]?, resolve:RCTPromiseResolveBlock, reject:RCTPromiseRejectBlock) -> Void {
        do {
            resolve(try self.encryptBytes(plainText: plainText,
                                          key: key,
                                          nonce: nonce,
                                          authenticatingData: authenticatingData))
        } catch CryptoError.runtimeError(let errorMessage) {
            reject("InvalidArgumentError", errorMessage, nil)
        } catch {
            reject("EncryptionError", "Failed to encrypt", error)
        }
    }

    @objc(encryptFile:outputFilePath:withKey:withResolver:withRejecter:)
    func encryptFile(inputFilePath: String, outputFilePath: String, key: String, resolve:RCTPromiseResolveBlock, reject:RCTPromiseRejectBlock) -> Void {
        do {
            let keyData = Data(base64Encoded: key)!
            let file = FileHandle.init(forReadingAtPath: inputFilePath)
            if (file == nil) {
                return reject("IOError", "IOError: Could not open file for reading: \(inputFilePath)", nil)
            }
            let plainData = file!.readDataToEndOfFile()
            
            let encryptedData = try self.encryptBytes(plainText: Array(plainData),
                                                      key: Array(keyData),
                                                      nonce: nil,
                                                      authenticatingData: nil)

            if let wfile = FileHandle.init(forWritingAtPath: outputFilePath) {
                wfile.write(Data(encryptedData["content"]!))
                wfile.closeFile()
            } else {
                return reject("IOError", "IOError: Could not open file for writing: \(outputFilePath)", nil)
            }

            let response: [String: [UInt8]] = [
                "iv": encryptedData["iv"]!,
                "tag": encryptedData["tag"]!
            ]
            
            resolve(response)
        } catch CryptoError.runtimeError(let errorMessage) {
            reject("InvalidArgumentError", errorMessage, nil)
        } catch {
            reject("EncryptionError", "Failed to encrypt", error)
        }
    }
}

