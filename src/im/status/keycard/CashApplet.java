package im.status.keycard;

import javacard.framework.*;
import javacard.security.*;

public class CashApplet extends Applet {
  private static final short SIGN_OUT_OFF = ISO7816.OFFSET_CDATA + MessageDigest.LENGTH_SHA_256;
  private static final byte TLV_PUB_DATA = (byte) 0x82;

  private KeyPair keypair;
  private ECPublicKey publicKey;
  private ECPrivateKey privateKey;

  private Crypto crypto;
  private SECP256k1 secp256k1;
  
  private byte[] BLS_TEST_SK = {
      (byte) 0x28, (byte) 0xb9, (byte) 0x0d, (byte) 0xea, (byte) 0xf1, (byte) 0x89, (byte) 0x01, (byte) 0x5d, 
      (byte) 0x3a, (byte) 0x32, (byte) 0x59, (byte) 0x08, (byte) 0xc5, (byte) 0xe0, (byte) 0xe4, (byte) 0xbf, 
      (byte) 0x00, (byte) 0xf8, (byte) 0x4f, (byte) 0x7e, (byte) 0x63, (byte) 0x9b, (byte) 0x05, (byte) 0x6f, 
      (byte) 0xf8, (byte) 0x2d, (byte) 0x7e, (byte) 0x70, (byte) 0xb6, (byte) 0xee, (byte) 0xde, (byte) 0x4c,       
  };
  
  private byte[] BLS_TEST_HASH = {
      (byte) 0x06, (byte) 0xD4, (byte) 0x06, (byte) 0x54, (byte) 0xFA, (byte) 0x9D, (byte) 0xE7, (byte) 0x33, 
      (byte) 0x6E, (byte) 0x47, (byte) 0x8B, (byte) 0x20, (byte) 0x7A, (byte) 0xFE, (byte) 0x75, (byte) 0x57, 
      (byte) 0x5E, (byte) 0x66, (byte) 0x3C, (byte) 0xC8, (byte) 0xC1, (byte) 0x8D, (byte) 0xF7, (byte) 0xAC, 
      (byte) 0x6C, (byte) 0x65, (byte) 0x9C, (byte) 0xC0, (byte) 0x12, (byte) 0x49, (byte) 0xA7, (byte) 0x26, 
      (byte) 0xE4, (byte) 0xA6, (byte) 0x7F, (byte) 0xE1, (byte) 0x9D, (byte) 0xFF, (byte) 0xCF, (byte) 0x06, 
      (byte) 0xF6, (byte) 0xAF, (byte) 0x5C, (byte) 0xF4, (byte) 0xE2, (byte) 0x52, (byte) 0x3A, (byte) 0x1A, 
      (byte) 0x02, (byte) 0x73, (byte) 0xEC, (byte) 0xC6, (byte) 0x19, (byte) 0xA1, (byte) 0x6D, (byte) 0x8D, 
      (byte) 0x34, (byte) 0xD7, (byte) 0x1A, (byte) 0xFD, (byte) 0xF7, (byte) 0x01, (byte) 0x25, (byte) 0x4A, 
      (byte) 0x3A, (byte) 0x30, (byte) 0xF2, (byte) 0x82, (byte) 0xAD, (byte) 0x50, (byte) 0x5A, (byte) 0xF9, 
      (byte) 0x08, (byte) 0xEC, (byte) 0xCC, (byte) 0xF2, (byte) 0xC6, (byte) 0xE6, (byte) 0xB3, (byte) 0x2D, 
      (byte) 0x95, (byte) 0xFE, (byte) 0xDF, (byte) 0xDA, (byte) 0x1D, (byte) 0x33, (byte) 0x1D, (byte) 0xF1, 
      (byte) 0x2E, (byte) 0xDD, (byte) 0x3A, (byte) 0x5D, (byte) 0x94, (byte) 0x85, (byte) 0xAD, (byte) 0xE0, 
      (byte) 0x18, (byte) 0x94, (byte) 0x63, (byte) 0xEA, (byte) 0xF6, (byte) 0x36, (byte) 0x21, (byte) 0xF0, 
      (byte) 0xB8, (byte) 0xA9, (byte) 0xE6, (byte) 0x6C, (byte) 0xA3, (byte) 0xF5, (byte) 0xAB, (byte) 0x70, 
      (byte) 0x1F, (byte) 0x0A, (byte) 0x0D, (byte) 0x36, (byte) 0x54, (byte) 0xD9, (byte) 0x14, (byte) 0x66, 
      (byte) 0xE7, (byte) 0xEB, (byte) 0xCF, (byte) 0x59, (byte) 0x69, (byte) 0x26, (byte) 0x34, (byte) 0xE0, 
      (byte) 0x2E, (byte) 0xCE, (byte) 0x77, (byte) 0x4A, (byte) 0xF8, (byte) 0x81, (byte) 0x20, (byte) 0xC2, 
      (byte) 0xB9, (byte) 0x30, (byte) 0x1C, (byte) 0x3E, (byte) 0xBA, (byte) 0xBA, (byte) 0x4E, (byte) 0x96, 
      (byte) 0x07, (byte) 0x59, (byte) 0x99, (byte) 0x3F, (byte) 0x1A, (byte) 0x4B, (byte) 0x48, (byte) 0x5C, 
      (byte) 0x54, (byte) 0x5D, (byte) 0x72, (byte) 0x32, (byte) 0x40, (byte) 0x85, (byte) 0x53, (byte) 0x4B, 
      (byte) 0xB3, (byte) 0xB8, (byte) 0x3D, (byte) 0xE7, (byte) 0x84, (byte) 0x2E, (byte) 0x03, (byte) 0x26, 
      (byte) 0xC7, (byte) 0x2A, (byte) 0x81, (byte) 0x53, (byte) 0x50, (byte) 0x8E, (byte) 0x07, (byte) 0x3B, 
      (byte) 0xDD, (byte) 0xD5, (byte) 0xA5, (byte) 0x4E, (byte) 0x83, (byte) 0x76, (byte) 0x34, (byte) 0x7A, 
      (byte) 0x61, (byte) 0xCC, (byte) 0x98, (byte) 0x7F, (byte) 0xD5, (byte) 0xB1, (byte) 0xE9, (byte) 0x53,        
  };

  /**
   * Invoked during applet installation. Creates an instance of this class. The installation parameters are passed in
   * the given buffer.
   *
   * @param bArray installation parameters buffer
   * @param bOffset offset where the installation parameters begin
   * @param bLength length of the installation parameters
   */
  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new CashApplet(bArray, bOffset, bLength);
  }

  /**
   * Application constructor. All memory allocation is done here. The reason for this is two-fold: first the card might
   * not have Garbage Collection so dynamic allocation will eventually eat all memory. The second reason is to be sure
   * that if the application installs successfully, there is no risk of running out of memory because of other applets
   * allocating memory. The constructor also registers the applet with the JCRE so that it becomes selectable.
   *
   * @param bArray installation parameters buffer
   * @param bOffset offset where the installation parameters begin
   * @param bLength length of the installation parameters
   */
  public CashApplet(byte[] bArray, short bOffset, byte bLength) {
    crypto = new Crypto();
    secp256k1 = new SECP256k1();

    keypair = new KeyPair(KeyPair.ALG_EC_FP, SECP256k1.SECP256K1_KEY_SIZE);
    publicKey = (ECPublicKey) keypair.getPublic();
    privateKey = (ECPrivateKey) keypair.getPrivate();
    secp256k1.setCurveParameters(publicKey);
    secp256k1.setCurveParameters(privateKey);
    keypair.genKeyPair();

    short c9Off = (short)(bOffset + bArray[bOffset] + 1); // Skip AID
    c9Off += (short)(bArray[c9Off] + 1); // Skip Privileges and parameter length

    short dataLen = Util.makeShort((byte) 0x00, bArray[c9Off]);
    if (dataLen > 0) {
      Util.arrayCopyNonAtomic(bArray, c9Off, SharedMemory.cashDataFile, (short) 0, (short)(dataLen + 1));
    }

    register(bArray, (short) (bOffset + 1), bArray[bOffset]);
  }

  public void process(APDU apdu) throws ISOException {
    apdu.setIncomingAndReceive();

    // Since selection can happen not only by a SELECT command, we check for that separately.
    if (selectingApplet()) {
      selectApplet(apdu);
      return;
    }

    byte[] apduBuffer = apdu.getBuffer();

    try {
      switch (apduBuffer[ISO7816.OFFSET_INS]) {
        case KeycardApplet.INS_SIGN:
          sign(apdu);
          break;
        default:
          ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
          break;
      }
    } catch (CryptoException ce) {
      ISOException.throwIt((short)(ISO7816.SW_UNKNOWN | ce.getReason()));
    } catch (Exception e) {
      ISOException.throwIt(ISO7816.SW_UNKNOWN);
    }
  }

  private void selectApplet(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();

    short off = 0;

    apduBuffer[off++] = KeycardApplet.TLV_APPLICATION_INFO_TEMPLATE;
    short lenoff = off++;

    apduBuffer[off++] = KeycardApplet.TLV_PUB_KEY;
    short keyLength = publicKey.getW(apduBuffer, (short) (off + 1));
    apduBuffer[off++] = (byte) keyLength;
    off += keyLength;

    apduBuffer[off++] = KeycardApplet.TLV_INT;
    apduBuffer[off++] = 2;
    Util.setShort(apduBuffer, off, KeycardApplet.APPLICATION_VERSION);
    off += 2;

    apduBuffer[off++] = TLV_PUB_DATA;
    apduBuffer[off++] = SharedMemory.cashDataFile[0];
    Util.arrayCopyNonAtomic(SharedMemory.cashDataFile, (short) 1, apduBuffer, off, SharedMemory.cashDataFile[0]);
    off += SharedMemory.cashDataFile[0];
    
    apduBuffer[lenoff] = (byte)(off - lenoff - 1);
    apdu.setOutgoingAndSend((short) 0, off);
  }

  private void sign(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();

    apduBuffer[SIGN_OUT_OFF] = KeycardApplet.TLV_SIGNATURE_TEMPLATE;
    short outLen = 3;

    if (apduBuffer[ISO7816.OFFSET_P2] == KeycardApplet.SIGN_P2_ECDSA) {
      apduBuffer[(short) (SIGN_OUT_OFF + 3)] = KeycardApplet.TLV_PUB_KEY;
      apduBuffer[(short) (SIGN_OUT_OFF + 4)] = Crypto.KEY_PUB_SIZE;
  
      publicKey.getW(apduBuffer, (short) (SIGN_OUT_OFF + 5));
  
      outLen += (short) (Crypto.KEY_PUB_SIZE + 2);
      outLen += secp256k1.ecdsaDeterministicSign(crypto, privateKey, apduBuffer, ISO7816.OFFSET_CDATA, apduBuffer, (short) (SIGN_OUT_OFF + outLen));      
    } else {
      apduBuffer[(short) (SIGN_OUT_OFF + 3)] = KeycardApplet.TLV_BLS_SIGNATURE;
      outLen += 2;
      short sigLen = secp256k1.blsSign(BLS_TEST_SK, (short) 0, BLS_TEST_HASH, (short) 0, apduBuffer, (short) (SIGN_OUT_OFF + outLen));
      apduBuffer[(short) (SIGN_OUT_OFF + 4)] = (byte) sigLen;
      outLen += sigLen;
    }
    
    apduBuffer[(short) (SIGN_OUT_OFF + 1)] = (byte) 0x81;
    apduBuffer[(short) (SIGN_OUT_OFF + 2)] = (byte) (outLen - 3);
    apdu.setOutgoingAndSend(SIGN_OUT_OFF, outLen);
  }
}
