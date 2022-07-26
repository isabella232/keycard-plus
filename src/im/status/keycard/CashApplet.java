package im.status.keycard;

import javacard.framework.*;
import javacard.security.*;

public class CashApplet extends Applet {
  private static final short SIGN_OUT_OFF = ISO7816.OFFSET_CDATA + MessageDigest.LENGTH_SHA_256;
  private static final byte TLV_PUB_DATA = (byte) 0x82;

  private KeyPair keypair;
  private KeyPair blsPair;
  
  private ECPublicKey publicKey;
  private ECPublicKey blsPublic;

  private ECPrivateKey privateKey;
  private ECPrivateKey blsPrivate;

  private Crypto crypto;
  private SECP256k1 secp256k1;
  
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
    SECP256k1.setCurveParameters(publicKey);
    SECP256k1.setCurveParameters(privateKey);
    keypair.genKeyPair();
    
    blsPair = new KeyPair(KeyPair.ALG_EC_FP, SECP256k1.BLS_KEY_SIZE);
    blsPublic = (ECPublicKey) blsPair.getPublic();
    blsPrivate = (ECPrivateKey) blsPair.getPrivate();
    secp256k1.setBLSCurveParameters(blsPublic);
    secp256k1.setBLSCurveParameters(blsPrivate);
    blsPair.genKeyPair();

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
        case IdentApplet.INS_IDENTIFY_CARD:
          IdentApplet.identifyCard(apdu, null, secp256k1, crypto);
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
    apduBuffer[off++] = (byte) 0x81;
    short lenoff = off++;

    apduBuffer[off++] = KeycardApplet.TLV_PUB_KEY;
    short keyLength = publicKey.getW(apduBuffer, (short) (off + 1));
    apduBuffer[off++] = (byte) keyLength;
    off += keyLength;
    
    apduBuffer[off++] = KeycardApplet.TLV_PUB_KEY;
    keyLength = blsPublic.getW(apduBuffer, (short) (off + 1));
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

    short outLen = 3;

    if (apduBuffer[ISO7816.OFFSET_P2] == KeycardApplet.SIGN_P2_ECDSA) {
      apduBuffer[(short) (SIGN_OUT_OFF + 3)] = KeycardApplet.TLV_PUB_KEY;
      apduBuffer[(short) (SIGN_OUT_OFF + 4)] = Crypto.KEY_PUB_SIZE;
  
      publicKey.getW(apduBuffer, (short) (SIGN_OUT_OFF + 5));
  
      outLen += (short) (Crypto.KEY_PUB_SIZE + 2);
      outLen += secp256k1.ecdsaDeterministicSign(crypto, privateKey, apduBuffer, ISO7816.OFFSET_CDATA, apduBuffer, (short) (SIGN_OUT_OFF + outLen));      
    } else {
      outLen += 2;
      short sigLen = secp256k1.blsSign(blsPrivate, apduBuffer, ISO7816.OFFSET_CDATA, apduBuffer, (short) (SIGN_OUT_OFF + outLen));
      apduBuffer[(short) (SIGN_OUT_OFF + 3)] = KeycardApplet.TLV_BLS_SIGNATURE;
      apduBuffer[(short) (SIGN_OUT_OFF + 4)] = (byte) sigLen;
      outLen += sigLen;
    }
    
    apduBuffer[SIGN_OUT_OFF] = KeycardApplet.TLV_SIGNATURE_TEMPLATE;
    
    apduBuffer[(short) (SIGN_OUT_OFF + 1)] = (byte) 0x81;
    apduBuffer[(short) (SIGN_OUT_OFF + 2)] = (byte) (outLen - 3);
    apdu.setOutgoingAndSend(SIGN_OUT_OFF, outLen);
  }
}
