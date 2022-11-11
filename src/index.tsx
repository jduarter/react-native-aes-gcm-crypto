import { NativeModules } from 'react-native';

export type EncryptedData = {
  iv: Uint8Array;
  tag: Uint8Array;
  content: Uint8Array;
};

type AesGcmCryptoType = {
  decrypt(
    ciphertext: Uint8Array,
    key: Uint8Array,
    iv: Uint8Array,
    tag: Uint8Array,
    associatedData?: Uint8Array
  ): Promise<Uint8Array>;
  decryptFile(
    inputFilePath: string,
    outputFilePath: string,
    key: string,
    iv: string,
    tag: string
  ): Promise<boolean>;
  encrypt(
    plainText: Uint8Array,
    key: Uint8Array,
    iv?: Uint8Array,
    associatedData?: Uint8Array
  ): Promise<EncryptedData>;
  encryptFile(
    inputFilePath: string,
    outputFilePath: string,
    key: string
  ): Promise<{
    iv: string;
    tag: string;
  }>;
};

const { AesGcmCrypto } = NativeModules;

const toUint8Array = (arr: Array<number>): Uint8Array => new Uint8Array(arr);
 

const WiredAesGcmCrypto = {
  encrypt: async (...args: any[]) => {
    const nativeArgs = [...args.map((a)=>([...a]))];
    while (nativeArgs.length < 4) {
      nativeArgs.push(null);
    }

    const r = await AesGcmCrypto.encrypt(...nativeArgs);

    return Object.getOwnPropertyNames(r).reduce(
      (last, curr) => ({
        ...last,
        [curr]: toUint8Array(r[curr]),
      }),
      {}
    );
  },
  decrypt: async (...args: any[]) =>
    toUint8Array(await AesGcmCrypto.decrypt(...args)),

  encryptFile: AesGcmCrypto.encryptFile,
  decryptFile: AesGcmCrypto.decryptFile,
};

export default WiredAesGcmCrypto as AesGcmCryptoType;
