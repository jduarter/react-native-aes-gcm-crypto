package com.reactnativeaesgcmcrypto

import com.facebook.react.bridge.*
import com.facebook.react.module.annotations.ReactModule
import java.io.File
import java.security.GeneralSecurityException
import java.util.*
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

import android.util.Log

class EncryptionOutput(val iv: ByteArray,
                       val tag: ByteArray,
                       val ciphertext: ByteArray)

@ReactModule(name = "AesGcmCrypto")
class AesGcmCryptoModule(reactContext: ReactApplicationContext) : ReactContextBaseJavaModule(reactContext) {
  val GCM_TAG_LENGTH = 16

  override fun getName(): String {
    return "AesGcmCrypto"
  }

  fun readableArrToByteArr (arr: ReadableArray): ByteArray {
    val elems = ByteArray(arr.size())

    for (i in 0..(arr.size()-1)) {
      elems[i] = arr.getInt(i).toByte()
    }

    return elems
  }

  fun byteArrayToReadableArray (arr: ByteArray): ReadableArray {
    val elems = Arguments.createArray()
 
    for (i in 0..(arr.size-1)) {
      elems.pushInt(arr[i].toInt() and 0xff)
    }

    return elems
  }

 /*
 fun rctArrDump(arrName:String, arr: ReadableArray?) {
    if (arr == null) {
      Log.d("AesGcmCrypto", arrName + " = null")
    } else {
      Log.d("AesGcmCrypto", arrName + " = " + readableArrToByteArr(arr).contentToString())
    }
  }
  */

  @Throws(javax.crypto.AEADBadTagException::class)
  fun decryptData(ciphertext: ByteArray, key: ByteArray, iv: ByteArray, tag: ByteArray, associatedData: ByteArray?): ByteArray {
    val secretKey: SecretKey = SecretKeySpec(key, 0, key.size, "AES")

    val cipher = Cipher.getInstance("AES/GCM/NoPadding")

    val spec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv)
    
    cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)

    if (associatedData != null) {
      cipher.updateAAD(associatedData)
    }

    return cipher.doFinal(ciphertext + tag)
  }

  @ReactMethod
  fun decrypt(ciphertext: ReadableArray,
              key: ReadableArray,
              iv: ReadableArray,
              tag: ReadableArray,
              associatedData: ReadableArray?,
              promise: Promise) {
    try {
      val unsealed = decryptData(
        readableArrToByteArr(ciphertext),
        readableArrToByteArr(key),
        readableArrToByteArr(iv),
        readableArrToByteArr(tag),
        if (associatedData != null) readableArrToByteArr(associatedData) else null)

      promise.resolve(byteArrayToReadableArray(unsealed))
    } catch (e: javax.crypto.AEADBadTagException) {
      promise.reject("DecryptionError", "Bad auth tag exception", e)
    } catch (e: GeneralSecurityException) {
      promise.reject("DecryptionError", "Failed to decrypt", e)
    } catch (e: Exception) {
      /*
      Log.d("AesGcmCrypto", "decrypt() ERROR: " + e.message)
      Log.d("AesGcmCrypto", "Stacktrace: " + e.stackTraceToString())
      */
      promise.reject("DecryptionError", "Unexpected error", e)
    }
  }

  @ReactMethod
  fun decryptFile(inputFilePath: String,
                  outputFilePath: String,
                  key: String,
                  iv: String,
                  tag: String,
                  promise: Promise) {
    try {
      val ciphertext = File(inputFilePath).inputStream().readBytes()
      val unsealed = decryptData(ciphertext, key.toByteArray(), iv.toByteArray(), tag.toByteArray(), null)

      File(outputFilePath).outputStream().write(unsealed)
      promise.resolve(true)
    } catch (e: javax.crypto.AEADBadTagException) {
      promise.reject("DecryptionError", "Bad auth tag exception", e)
    } catch (e: GeneralSecurityException) {
      promise.reject("DecryptionError", "Failed to decrypt", e)
    } catch (e: Exception) {
      promise.reject("DecryptionError", "Unexpected error", e)
    }
  }

  fun encryptData(plainData: ByteArray, key: ByteArray, iv: ByteArray?, associatedData: ByteArray?): EncryptionOutput {
    val secretKey: SecretKey = SecretKeySpec(key, 0, key.size, "AES")

    val cipher = Cipher.getInstance("AES/GCM/NoPadding")

    if (iv != null) {
      cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_LENGTH * 8, iv))
    } else {
      cipher.init(Cipher.ENCRYPT_MODE, secretKey)
    }
    
    if (associatedData != null) {
      cipher.updateAAD(associatedData)
    }

    val result = cipher.doFinal(plainData)

    val ciphertext = result.copyOfRange(0, result.size - GCM_TAG_LENGTH)
    val tag = result.copyOfRange(result.size - GCM_TAG_LENGTH, result.size)

    val usedIV = cipher.iv.copyOf()

    return EncryptionOutput(usedIV, tag, ciphertext)
  }

  @ReactMethod
  fun encrypt(plainData: ReadableArray,
              key: ReadableArray,
              iv: ReadableArray?,
              associatedData: ReadableArray?,
              promise: Promise) {
    try {
      val sealed = encryptData(
        readableArrToByteArr(plainData),
        readableArrToByteArr(key),
        if (iv != null) readableArrToByteArr(iv) else null,
        if (associatedData != null) readableArrToByteArr(associatedData) else null,
      )

      var response = WritableNativeMap()

      response.putArray("iv", byteArrayToReadableArray(sealed.iv))
      response.putArray("tag", byteArrayToReadableArray(sealed.tag))
      response.putArray("content", byteArrayToReadableArray(sealed.ciphertext))

      promise.resolve(response)
    } catch (e: GeneralSecurityException) {
      promise.reject("EncryptionError", "Failed to encrypt", e)
    } catch (e: Exception) {
      /*
      Log.d("AesGcmCrypto", "encrypt() ERROR: " + e.message)
      Log.d("AesGcmCrypto", "Stacktrace: " + e.stackTraceToString())
      */
      promise.reject("EncryptionError", "Unexpected error", e)
    }
  }

  @ReactMethod
  fun encryptFile(inputFilePath: String,
                  outputFilePath: String,
                  key: String,
                  promise: Promise) {
    try {
      val keyData = Base64.getDecoder().decode(key)
      val plainData = File(inputFilePath).inputStream().readBytes()
      val sealed = encryptData(plainData, keyData, null, null)
      File(outputFilePath).outputStream().write(sealed.ciphertext)
      var response = WritableNativeMap()
      response.putString("iv", sealed.iv.toHex())
      response.putString("tag", sealed.tag.toHex())
      promise.resolve(response)
    } catch (e: GeneralSecurityException) {
      promise.reject("EncryptionError", "Failed to encrypt", e)
    } catch (e: Exception) {
      promise.reject("EncryptionError", "Unexpected error", e)
    }
  }
}
