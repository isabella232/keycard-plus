package im.status.keycard;

import com.nxp.id.jcopx.securebox.SecureBox;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;

/**
 * Utility methods to work with the SECP256k1 curve.
 */
public class SECP256k1 {
  static final byte SECP256K1_FP[] = {
      (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
      (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
      (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
      (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,(byte)0xFF,(byte)0xFF,(byte)0xFC,(byte)0x2F
  };
  static final byte SECP256K1_A[] = {
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00
  };
  static final byte SECP256K1_B[] = {
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x07
  };
  static final byte SECP256K1_G[] = {
      (byte)0x04,
      (byte)0x79,(byte)0xBE,(byte)0x66,(byte)0x7E,(byte)0xF9,(byte)0xDC,(byte)0xBB,(byte)0xAC,
      (byte)0x55,(byte)0xA0,(byte)0x62,(byte)0x95,(byte)0xCE,(byte)0x87,(byte)0x0B,(byte)0x07,
      (byte)0x02,(byte)0x9B,(byte)0xFC,(byte)0xDB,(byte)0x2D,(byte)0xCE,(byte)0x28,(byte)0xD9,
      (byte)0x59,(byte)0xF2,(byte)0x81,(byte)0x5B,(byte)0x16,(byte)0xF8,(byte)0x17,(byte)0x98,
      (byte)0x48,(byte)0x3A,(byte)0xDA,(byte)0x77,(byte)0x26,(byte)0xA3,(byte)0xC4,(byte)0x65,
      (byte)0x5D,(byte)0xA4,(byte)0xFB,(byte)0xFC,(byte)0x0E,(byte)0x11,(byte)0x08,(byte)0xA8,
      (byte)0xFD,(byte)0x17,(byte)0xB4,(byte)0x48,(byte)0xA6,(byte)0x85,(byte)0x54,(byte)0x19,
      (byte)0x9C,(byte)0x47,(byte)0xD0,(byte)0x8F,(byte)0xFB,(byte)0x10,(byte)0xD4,(byte)0xB8
  };
  static final byte SECP256K1_R[] = {
      (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
      (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,
      (byte)0xBA,(byte)0xAE,(byte)0xDC,(byte)0xE6,(byte)0xAF,(byte)0x48,(byte)0xA0,(byte)0x3B,
      (byte)0xBF,(byte)0xD2,(byte)0x5E,(byte)0x8C,(byte)0xD0,(byte)0x36,(byte)0x41,(byte)0x41
  };
  
  static final byte SECP256K1_K = (byte)0x01;

  static final short SECP256K1_KEY_SIZE = 256;
 
  static final byte BLS_FP[] = {
      (byte)0x1a,(byte)0x01,(byte)0x11,(byte)0xea,(byte)0x39,(byte)0x7f,(byte)0xe6,(byte)0x9a,
      (byte)0x4b,(byte)0x1b,(byte)0xa7,(byte)0xb6,(byte)0x43,(byte)0x4b,(byte)0xac,(byte)0xd7,
      (byte)0x64,(byte)0x77,(byte)0x4b,(byte)0x84,(byte)0xf3,(byte)0x85,(byte)0x12,(byte)0xbf,
      (byte)0x67,(byte)0x30,(byte)0xd2,(byte)0xa0,(byte)0xf6,(byte)0xb0,(byte)0xf6,(byte)0x24,
      (byte)0x1e,(byte)0xab,(byte)0xff,(byte)0xfe,(byte)0xb1,(byte)0x53,(byte)0xff,(byte)0xff,
      (byte)0xb9,(byte)0xfe,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xaa,(byte)0xab,
  };
 
  static final byte BLS_A[] = {
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,      
  };
  
  static final byte BLS_B[] = {
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x04,      
  };
  
  static final byte BLS_G[] = {
      (byte)0x04,     
      (byte)0x17,(byte)0xf1,(byte)0xd3,(byte)0xa7,(byte)0x31,(byte)0x97,(byte)0xd7,(byte)0x94,
      (byte)0x26,(byte)0x95,(byte)0x63,(byte)0x8c,(byte)0x4f,(byte)0xa9,(byte)0xac,(byte)0x0f,
      (byte)0xc3,(byte)0x68,(byte)0x8c,(byte)0x4f,(byte)0x97,(byte)0x74,(byte)0xb9,(byte)0x05,
      (byte)0xa1,(byte)0x4e,(byte)0x3a,(byte)0x3f,(byte)0x17,(byte)0x1b,(byte)0xac,(byte)0x58,
      (byte)0x6c,(byte)0x55,(byte)0xe8,(byte)0x3f,(byte)0xf9,(byte)0x7a,(byte)0x1a,(byte)0xef,
      (byte)0xfb,(byte)0x3a,(byte)0xf0,(byte)0x0a,(byte)0xdb,(byte)0x22,(byte)0xc6,(byte)0xbb,
      (byte)0x08,(byte)0xb3,(byte)0xf4,(byte)0x81,(byte)0xe3,(byte)0xaa,(byte)0xa0,(byte)0xf1,
      (byte)0xa0,(byte)0x9e,(byte)0x30,(byte)0xed,(byte)0x74,(byte)0x1d,(byte)0x8a,(byte)0xe4,
      (byte)0xfc,(byte)0xf5,(byte)0xe0,(byte)0x95,(byte)0xd5,(byte)0xd0,(byte)0x0a,(byte)0xf6,
      (byte)0x00,(byte)0xdb,(byte)0x18,(byte)0xcb,(byte)0x2c,(byte)0x04,(byte)0xb3,(byte)0xed,
      (byte)0xd0,(byte)0x3c,(byte)0xc7,(byte)0x44,(byte)0xa2,(byte)0x88,(byte)0x8a,(byte)0xe4,
      (byte)0x0c,(byte)0xaa,(byte)0x23,(byte)0x29,(byte)0x46,(byte)0xc5,(byte)0xe7,(byte)0xe1,      
  };
  
  static final byte BLS_R[] = {
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,      
      (byte)0x73,(byte)0xed,(byte)0xa7,(byte)0x53,(byte)0x29,(byte)0x9d,(byte)0x7d,(byte)0x48,
      (byte)0x33,(byte)0x39,(byte)0xd8,(byte)0x08,(byte)0x09,(byte)0xa1,(byte)0xd8,(byte)0x05,
      (byte)0x53,(byte)0xbd,(byte)0xa4,(byte)0x02,(byte)0xff,(byte)0xfe,(byte)0x5b,(byte)0xfe,
      (byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01,      
  };  

  static final short BLS_KEY_SIZE = 384;
  static final short BLS_SK_SIZE = 32;
  static final short BLS_HASH_SIZE = 192;

  private static final short ECDSABUF_SIZE = (short) 128;
  private static final short BLSBUF_SIZE = (short) 224;
  private static final short SB_BLS = (short) 1;
  private static final short SB_ECDSA = (short) 2;
  
  private static final short ECDSA_SK_OFF = (short) 0;
  private static final short ECDSA_R_OFF = (short) 32;
  private static final short ECDSA_TMP_R_OFF = (short) ECDSA_R_OFF - 1;
  private static final short ECDSA_H_OFF = (short) 64;
  private static final short ECDSA_K_OFF = (short) 96;  
  
  static final byte TLV_SIGNATURE_TEMPLATE = (byte) 0xA0;
  static final byte TLV_RAW_SIGNATURE = (byte) 0x80;
  static final byte TLV_PUB_KEY = (byte) 0x80;

  private KeyAgreement ecPointMultiplier;
  private byte[] sigBuf;

  ECPrivateKey tmpECPrivateKey;

  /**
   * Allocates objects needed by this class. Must be invoked during the applet installation exactly 1 time.
   */
  SECP256k1() {
    this.sigBuf = JCSystem.makeTransientByteArray(BLSBUF_SIZE, JCSystem.CLEAR_ON_DESELECT); 
    this.ecPointMultiplier = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false);
    this.tmpECPrivateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, SECP256K1_KEY_SIZE, false);
    setCurveParameters(tmpECPrivateKey);
  }

  /**
   * Sets the SECP256k1 curve parameters to the given ECKey (public or private).
   *
   * @param key the key where the curve parameters must be set
   */
  static void setCurveParameters(ECKey key) {
    key.setA(SECP256K1_A, (short) 0x00, (short) SECP256K1_A.length);
    key.setB(SECP256K1_B, (short) 0x00, (short) SECP256K1_B.length);
    key.setFieldFP(SECP256K1_FP, (short) 0x00, (short) SECP256K1_FP.length);
    key.setG(SECP256K1_G, (short) 0x00, (short) SECP256K1_G.length);
    key.setR(SECP256K1_R, (short) 0x00, (short) SECP256K1_R.length);
    key.setK(SECP256K1_K);
  }
  
  /**
   * Sets the BLS12-381 curve parameters to the given ECKey (public or private).
   *
   * @param key the key where the curve parameters must be set
   */
  void setBLSCurveParameters(ECKey key) {
    key.setA(BLS_A, (short) 0x00, (short) BLS_A.length);
    key.setB(BLS_B, (short) 0x00, (short) BLS_B.length);
    key.setFieldFP(BLS_FP, (short) 0x00, (short) BLS_FP.length);
    key.setG(BLS_G, (short) 0x00, (short) BLS_G.length);
    key.setR(BLS_R, (short) 0x00, (short) BLS_R.length);
  }

  /**
   * Derives the public key from the given private key and outputs it in the pubOut buffer. This is done by multiplying
   * the private key by the G point of the curve.
   *
   * @param privateKey the private key
   * @param pubOut the output buffer for the public key
   * @param pubOff the offset in pubOut
   * @return the length of the public key
   */
  short derivePublicKey(ECPrivateKey privateKey, byte[] pubOut, short pubOff) {
    return multiplyPoint(privateKey, SECP256K1_G, (short) 0, (short) SECP256K1_G.length, pubOut, pubOff);
  }


  /**
   * Derives the public key from the given private key and outputs it in the pubOut buffer. This is done by multiplying
   * the private key by the G point of the curve.
   *
   * @param privateKey the private key
   * @param pubOut the output buffer for the public key
   * @param pubOff the offset in pubOut
   * @return the length of the public key
   */
  short derivePublicKey(byte[] privateKey, short privOff, byte[] pubOut, short pubOff) {
    tmpECPrivateKey.setS(privateKey, privOff, (short)(SECP256K1_KEY_SIZE/8));
    return derivePublicKey(tmpECPrivateKey, pubOut, pubOff);
  }

  /**
   * Multiplies a scalar in the form of a private key by the given point. Internally uses a special version of EC-DH
   * supported since JavaCard 3.0.5 which outputs both X and Y in their uncompressed form.
   *
   * @param privateKey the scalar in a private key object
   * @param point the point to multiply
   * @param pointOff the offset of the point
   * @param pointLen the length of the point
   * @param out the output buffer
   * @param outOff the offset in the output buffer
   * @return the length of the data written in the out buffer
   */
  short multiplyPoint(ECPrivateKey privateKey, byte[] point, short pointOff, short pointLen, byte[] out, short outOff) {
    ecPointMultiplier.init(privateKey);
    return ecPointMultiplier.generateSecret(point, pointOff, pointLen, out, outOff);
  }
  
  void setSigningKey(ECPrivateKey privateKey) {
    if (privateKey.getS(sigBuf, (short) 0) == (short) 48) {
      Util.arrayCopyNonAtomic(sigBuf, (short) 16, sigBuf, (short) 0, BLS_SK_SIZE);
    }
  }
  
  void setSigningKey(byte[] privateKey, short off) {
    Util.arrayCopyNonAtomic(privateKey, off, sigBuf, (short) 0, (short) 32);
  }
  
  short ecdsaLegacySign(Crypto crypto, byte[] hash, short hashOff, byte[] out, short outOff) {
    out[outOff] = TLV_SIGNATURE_TEMPLATE;
    out[(short)(outOff + 3)] = TLV_PUB_KEY;
    out[(short)(outOff + 4)] = Crypto.KEY_PUB_SIZE;

    derivePublicKey(sigBuf, ECDSA_SK_OFF, out, (short) (outOff + 5));

    short outLen = (short) (Crypto.KEY_PUB_SIZE + 5);   
    
    outLen += ecdsaDERSign(crypto, hash, hashOff, out, (short)(outOff + outLen)); 
    
    out[(short)(outOff + 1)] = (byte) 0x81;
    out[(short)(outOff + 2)] = (byte) (outLen - 3);
    
    return outLen;
  }
  
  short ecdsaDERSign(Crypto crypto, byte[] hash, short hashOff, byte[] out, short outOff) {
    ecdsaDeterministicSign(crypto, hash, hashOff, sigBuf, (short) 0);
    
    short i = outOff;    

    byte rlen = 32;
    byte slen = 32;
    
    if ((sigBuf[2] & (byte) 0x80) == (byte) 0x80) {
      rlen++;
    }

    if ((sigBuf[34] & (byte) 0x80) == (byte) 0x80) {
      slen++;
    }

    out[i++] = (byte) 0x30;
    out[i++] = (byte) (slen + rlen + 4);
    out[i++] = (byte) 0x02;  
    out[i++] = rlen;
    if (rlen == 33) {
      out[i++] = 0x00;
    }
    Util.arrayCopyNonAtomic(sigBuf, (short) 2, out, i, (short) 32);
    i += 32;
    
    out[i++] = (byte) 0x02;  
    out[i++] = slen;  
    if (slen == 33) {
      out[i++] = 0x00;
    }
    Util.arrayCopyNonAtomic(sigBuf, (short) 34, out, i, (short) 32);
    i += 32;
    
    return (short)(i - outOff);
  }
  
  short ecdsaDeterministicSign(Crypto crypto, byte[] hash, short hashOff, byte[] out, short outOff) {    
    short count = 0;
    short outlen;
    
    outOff += 2;
    
    while(true) {
      crypto.rfc6979_256(hash, hashOff, sigBuf, ECDSA_SK_OFF, sigBuf, ECDSA_K_OFF, count++);
      
      if (crypto.isZero256(sigBuf, ECDSA_K_OFF) || crypto.ucmp256(sigBuf, ECDSA_K_OFF, SECP256K1_R, (short) 0) >= 0) {
        continue;
      }
      
      byte t = sigBuf[ECDSA_TMP_R_OFF];
      derivePublicKey(sigBuf, ECDSA_K_OFF, sigBuf, ECDSA_TMP_R_OFF);
      sigBuf[ECDSA_TMP_R_OFF] = t;
      
      if (crypto.isZero256(sigBuf, ECDSA_R_OFF)) {
        continue;
      }
      
      byte recId = (byte) (sigBuf[(short)(ECDSA_R_OFF + 63)] & 1);
      
      Util.arrayCopyNonAtomic(hash, hashOff, sigBuf, ECDSA_H_OFF, MessageDigest.LENGTH_SHA_256);
      outlen = SecureBox.runNativeLib(SB_ECDSA, null, null, null, null, null, sigBuf, (short) 0, ECDSABUF_SIZE, out, outOff);
      
      if (outlen > 0) {
        out[(short) (outOff + outlen - 1)] ^= recId;
        if (crypto.ucmp256(out, outOff, SECP256K1_R, (short) 0) >= 0) {
          recId += 2;
        }
        break;
      }
    }
    
    out[--outOff] = (byte) 65;
    out[--outOff] = TLV_RAW_SIGNATURE;
    
    return (short) (outlen + 2);
  }
  
  short blsSign(byte[] hash, short hashOff, byte[] out, short outOff) {    
    Util.arrayCopyNonAtomic(hash, hashOff, sigBuf, BLS_SK_SIZE, BLS_HASH_SIZE);    
    short outlen = SecureBox.runNativeLib(SB_BLS, null, null, null, null, null, sigBuf, (short) 0, BLSBUF_SIZE, out, (short) (outOff + 3));
    out[outOff] = TLV_RAW_SIGNATURE;
    out[(short)(outOff+1)] = (byte) 0x81;
    out[(short)(outOff+2)] = (byte) outlen;
    return (short) (outlen + 3);
  }  
}
