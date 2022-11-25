package im.status.keycard;

import com.nxp.id.jcopx.math.Math;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.*;
import javacardx.crypto.Cipher;

/**
 * Crypto utilities, mostly BIP32 related.
 */
public class Crypto {
  final static public short AES_BLOCK_SIZE = 16;

  final static short KEY_SECRET_SIZE = 32;
  final static short KEY_PUB_SIZE = 65;
  final static short KEY_DERIVATION_SCRATCH_SIZE = 37;
  final static private short HMAC512_OUT_SIZE = 64;
  final static private short HMAC256_OUT_SIZE = 32;
  
  final static private short RFC6979_K_OFF = 0;
  final static private short RFC6979_V_OFF = KEY_SECRET_SIZE;
  final static private short RFC6979_C_OFF = RFC6979_V_OFF + KEY_SECRET_SIZE;
  final static private short RFC6979_X_OFF = RFC6979_C_OFF + 1;
  final static private short RFC6979_H_OFF = RFC6979_X_OFF + KEY_SECRET_SIZE;
  final static private short RFC6979_OUT_OFF = RFC6979_H_OFF + KEY_SECRET_SIZE;
  final static private short RFC6979_SIZE = RFC6979_OUT_OFF + KEY_SECRET_SIZE;
  final static private short RFC6979_DATA_SIZE = RFC6979_SIZE - (KEY_SECRET_SIZE*2);

  final static private byte HMAC_IPAD = (byte) 0x36;
  final static private byte HMAC_OPAD = (byte) 0x5c;
  final static private short HMAC512_BLOCK_SIZE = (short) 128;
  final static private short HMAC256_BLOCK_SIZE = (short) 64;

  final static private byte[] KEY_BITCOIN_SEED = {'B', 'i', 't', 'c', 'o', 'i', 'n', ' ', 's', 'e', 'e', 'd'};

  // The below 5 objects can be accessed anywhere from the entire applet
  RandomData random;
  KeyAgreement ecdh;
  MessageDigest sha256;
  MessageDigest sha512;
  Cipher aesCbcIso9797m2;

  private byte[] hmacBlock;
  private byte[] rfc6979;

  Crypto() {
    random = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
    sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    ecdh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
    sha512 = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);
    aesCbcIso9797m2 = Cipher.getInstance(Cipher.ALG_AES_CBC_ISO9797_M2,false);
    hmacBlock = JCSystem.makeTransientByteArray(HMAC512_BLOCK_SIZE, JCSystem.CLEAR_ON_RESET);
    rfc6979 = JCSystem.makeTransientByteArray(RFC6979_SIZE, JCSystem.CLEAR_ON_RESET);
  }

  boolean bip32IsHardened(byte[] i, short iOff) {
    return (i[iOff] & (byte) 0x80) == (byte) 0x80;
  }

  /**
   * Derives a private key according to the algorithm defined in BIP32. The BIP32 specifications define some checks
   * to be performed on the derived keys. In the very unlikely event that these checks fail this key is not considered
   * to be valid so the derived key is discarded and this method returns false.
   *
   * @param i the buffer containing the key path element (a 32-bit big endian integer)
   * @param iOff the offset in the buffer
   * @return true if successful, false otherwise
   */
  boolean bip32CKDPriv(byte[] i, short iOff, byte[] scratch, short scratchOff, byte[] data, short dataOff, byte[] output, short outOff) {
    short off = scratchOff;

    if (bip32IsHardened(i, iOff)) {
      scratch[off++] = 0;
      off = Util.arrayCopyNonAtomic(data, dataOff, scratch, off, KEY_SECRET_SIZE);
    } else {
      scratch[off++] = ((data[(short) (dataOff + KEY_SECRET_SIZE + KEY_SECRET_SIZE + KEY_PUB_SIZE - 1)] & 1) != 0 ? (byte) 0x03 : (byte) 0x02);
      off = Util.arrayCopyNonAtomic(data, (short) (dataOff + KEY_SECRET_SIZE + KEY_SECRET_SIZE + 1), scratch, off, KEY_SECRET_SIZE);
    }

    off = Util.arrayCopyNonAtomic(i, iOff, scratch, off, (short) 4);

    hmacSHA512(data, (short)(dataOff + KEY_SECRET_SIZE), KEY_SECRET_SIZE, scratch, scratchOff, (short)(off - scratchOff), output, outOff);

    if (ucmp256(output, outOff, SECP256k1.SECP256K1_R, (short) 0) >= 0) {
      return false;
    }

    Math.modularAdd(output, outOff, KEY_SECRET_SIZE, data, dataOff, KEY_SECRET_SIZE, SECP256k1.SECP256K1_R, (short) 0, KEY_SECRET_SIZE);

    return !isZero256(output, outOff);
  }

  /**
   * Applies the algorithm for master key derivation defined by BIP32 to the binary seed provided as input.
   *
   * @param seed the binary seed
   * @param seedOff the offset of the binary seed
   * @param seedSize the size of the binary seed
   * @param masterKey the output buffer
   * @param keyOff the offset in the output buffer
   */
  void bip32MasterFromSeed(byte[] seed, short seedOff, short seedSize, byte[] masterKey, short keyOff) {
    hmacSHA512(KEY_BITCOIN_SEED, (short) 0, (short) KEY_BITCOIN_SEED.length, seed, seedOff, seedSize, masterKey, keyOff);
  }

  /**
   * Calculates the HMAC-SHA512 with the given key and data. Uses a software implementation which only requires SHA-512
   * to be supported on cards which do not have native HMAC-SHA512.
   *
   * @param key the HMAC key
   * @param keyOff the offset of the key
   * @param keyLen the length of the key
   * @param in the input data
   * @param inOff the offset of the input data
   * @param inLen the length of the input data
   * @param out the output buffer
   * @param outOff the offset in the output buffer
   */
  private void hmacSHA512(byte[] key, short keyOff, short keyLen, byte[] in, short inOff, short inLen, byte[] out, short outOff) {
    for (byte i = 0; i < 2; i++) {
      Util.arrayFillNonAtomic(hmacBlock, (short) 0, HMAC512_BLOCK_SIZE, (i == 0 ? HMAC_IPAD : HMAC_OPAD));

      for (short j = 0; j < keyLen; j++) {
        hmacBlock[j] ^= key[(short)(keyOff + j)];
      }

      sha512.update(hmacBlock, (short) 0, HMAC512_BLOCK_SIZE);

      if (i == 0) {
        sha512.doFinal(in, inOff, inLen, out, outOff);
      } else {
        sha512.doFinal(out, outOff, HMAC512_OUT_SIZE, out, outOff);
      }
    }
  }
  
  private void hmacSHA256(byte[] key, short keyOff, short keyLen, byte[] in, short inOff, short inLen, byte[] out, short outOff) {
    for (byte i = 0; i < 2; i++) {
      Util.arrayFillNonAtomic(hmacBlock, (short) 0, HMAC256_BLOCK_SIZE, (i == 0 ? HMAC_IPAD : HMAC_OPAD));
  
      for (short j = 0; j < keyLen; j++) {
        hmacBlock[j] ^= key[(short)(keyOff + j)];
      }
  
      sha256.update(hmacBlock, (short) 0, HMAC256_BLOCK_SIZE);
  
      if (i == 0) {
        sha256.doFinal(in, inOff, inLen, out, outOff);
      } else {
        sha256.doFinal(out, outOff, HMAC256_OUT_SIZE, out, outOff);
      }
    }
  }
  
  void rfc6979_256(byte[] hash, short hashOff, byte[] privKey, short privKeyOff, byte[] out, short outOff) {
    Util.arrayFillNonAtomic(rfc6979, RFC6979_K_OFF, KEY_SECRET_SIZE, (byte) 0x00);
    Util.arrayFillNonAtomic(rfc6979, RFC6979_V_OFF, KEY_SECRET_SIZE, (byte) 0x01);    
    Util.arrayCopyNonAtomic(privKey, privKeyOff, rfc6979, RFC6979_X_OFF, KEY_SECRET_SIZE);
    Util.arrayCopyNonAtomic(hash, hashOff, rfc6979, RFC6979_H_OFF, KEY_SECRET_SIZE); //TODO: missing modulo

    rfc6979[RFC6979_C_OFF] = (byte) 0x00;
    hmacSHA256(rfc6979, RFC6979_K_OFF, KEY_SECRET_SIZE, rfc6979, RFC6979_V_OFF, RFC6979_DATA_SIZE, rfc6979, RFC6979_OUT_OFF);
    Util.arrayCopyNonAtomic(rfc6979, RFC6979_OUT_OFF, rfc6979, RFC6979_K_OFF, KEY_SECRET_SIZE);
    hmacSHA256(rfc6979, RFC6979_K_OFF, KEY_SECRET_SIZE, rfc6979, RFC6979_V_OFF, KEY_SECRET_SIZE, rfc6979, RFC6979_OUT_OFF);
    Util.arrayCopyNonAtomic(rfc6979, RFC6979_OUT_OFF, rfc6979, RFC6979_V_OFF, KEY_SECRET_SIZE);
    
    rfc6979[RFC6979_C_OFF] = (byte) 0x01;
    hmacSHA256(rfc6979, RFC6979_K_OFF, KEY_SECRET_SIZE, rfc6979, RFC6979_V_OFF, RFC6979_DATA_SIZE, rfc6979, RFC6979_OUT_OFF);
    Util.arrayCopyNonAtomic(rfc6979, RFC6979_OUT_OFF, rfc6979, RFC6979_K_OFF, KEY_SECRET_SIZE);
    hmacSHA256(rfc6979, RFC6979_K_OFF, KEY_SECRET_SIZE, rfc6979, RFC6979_V_OFF, KEY_SECRET_SIZE, rfc6979, RFC6979_OUT_OFF);
    Util.arrayCopyNonAtomic(rfc6979, RFC6979_OUT_OFF, rfc6979, RFC6979_V_OFF, KEY_SECRET_SIZE);
    
    hmacSHA256(rfc6979, RFC6979_K_OFF, KEY_SECRET_SIZE, rfc6979, RFC6979_V_OFF, KEY_SECRET_SIZE, out, outOff); //TODO: missing checks/loop    
  }

  /**
   * Compares two 256-bit numbers. Returns a positive number if a > b, a negative one if a < b and 0 if a = b.
   *
   * @param a the a operand
   * @param aOff the offset of the a operand
   * @param b the b operand
   * @param bOff the offset of the b operand
   * @return the comparison result
   */
  private short ucmp256(byte[] a, short aOff, byte[] b, short bOff) {
    short gt = 0;
    short eq = 1;
    
    for (short i = 0 ; i < 32; i++) {
      short l = (short)(a[(short)(aOff + i)] & 0x00ff);
      short r = (short)(b[(short)(bOff + i)] & 0x00ff);
      short d = (short)(r - l);
      short l_xor_r = (short)(l ^ r);
      short l_xor_d = (short)(l ^ d);
      short d_xored = (short)(d ^ (short)(l_xor_r & l_xor_d));

      gt |= (d_xored >>> 15) & eq;
      eq &= ((short)(l_xor_r - 1) >>> 15);
    }

    return (short) ((gt + gt + eq) - 1);
  }

  /**
   * Checks if the given 256-bit number is 0.
   *
   * @param a the a operand
   * @param aOff the offset of the a operand
   * @return true if a is 0, false otherwise
   */
  private boolean isZero256(byte[] a, short aOff) {
    byte acc = 0;

    for (short i = 0; i < 32; i++) {
      acc |= a[(short)(aOff + i)];
    }

    return acc == 0;
  }
}
