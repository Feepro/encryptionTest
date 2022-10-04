package com.example.encryptiontest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public enum MacAlgorithm {

    NULL("null", 0, 0),
    AEAD("null", 0, 0),
    SSLMAC_MD5("SslMacMD5", 16, 16), // supported
    // by
    // SunJCE
    SSLMAC_SHA1("SslMacSHA1", 20, 20), // supported by SunJCE
    HMAC_MD5("HmacMD5", 16, 16),
    HMAC_SHA1("HmacSHA1", 20, 20),
    HMAC_SHA256("HmacSHA256", 32, 32),
    HMAC_SHA384("HmacSHA384", 48, 48),
    HMAC_SHA512("HmacSHA512", 64, 64),
    IMIT_GOST28147("GOST28147MAC", 4, 32),
    HMAC_GOSTR3411("HmacGOST3411", 32, 32),
    HMAC_GOSTR3411_2012_256("HmacGOST3411-2012-256", 32, 32);

    private final int size;
    private final int keySize;

    MacAlgorithm(String javaName, int size, int keySize) {
        this.javaName = javaName;
        this.size = size;
        this.keySize = keySize;
    }

    private final String javaName;

    public String getJavaName() {
        return javaName;
    }

    public int getSize() {
        return size;
    }

    public int getKeySize() {
        return keySize;
    }

    public enum HKDFAlgorithm {

        TLS_HKDF_SHA256(MacAlgorithm.HMAC_SHA256),
        TLS_HKDF_SHA384(MacAlgorithm.HMAC_SHA384);

        private HKDFAlgorithm(MacAlgorithm macAlgorithm) {
            this.macAlgorithm = macAlgorithm;
        }

        private final MacAlgorithm macAlgorithm;

        public MacAlgorithm getMacAlgorithm() {
            return macAlgorithm;
        }

    }

    public static class HKDFunction {

        public static final String KEY = "key";

        public static final String IV = "iv";

        public static final String FINISHED = "finished";

        public static final String DERIVED = "derived";

        public static final String BINDER_KEY_EXT = "ext binder";

        public static final String BINDER_KEY_RES = "res binder";

        public static final String CLIENT_EARLY_TRAFFIC_SECRET = "c e traffic";

        public static final String EARLY_EXPORTER_MASTER_SECRET = "e exp master";

        public static final String CLIENT_HANDSHAKE_TRAFFIC_SECRET = "c hs traffic";

        public static final String SERVER_HANDSHAKE_TRAFFIC_SECRET = "s hs traffic";

        public static final String CLIENT_APPLICATION_TRAFFIC_SECRET = "c ap traffic";

        public static final String SERVER_APPLICATION_TRAFFIC_SECRET = "s ap traffic";

        public static final String EXPORTER_MASTER_SECRET = "exp master";

        public static final String ESNI_IV = "esni iv";

        public static final String ESNI_KEY = "esni key";

        public static final String RESUMPTION_MASTER_SECRET = "res master";

        public static final String RESUMPTION = "resumption";

        public static final String TRAFFICUPD = "traffic upd";

        public HKDFunction() {
        }

        public static byte[] extract(HKDFAlgorithm hkdfAlgorithm, byte[] salt, byte[] ikm) throws CryptoException {
            try {
                Mac mac = Mac.getInstance(hkdfAlgorithm.getMacAlgorithm().getJavaName());
                if (salt == null || salt.length == 0) {
                    salt = new byte[mac.getMacLength()];
                    Arrays.fill(salt, (byte) 0);
                }
                SecretKeySpec keySpec = new SecretKeySpec(salt, hkdfAlgorithm.getMacAlgorithm().getJavaName());
                mac.init(keySpec);
                mac.update(ikm);
                return mac.doFinal();
            } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
                throw new CryptoException(ex);
            }
        }


        public static byte[] expand(HKDFAlgorithm hkdfAlgorithm, byte[] prk, byte[] info, int outLen)
                throws CryptoException {
            try {
                Mac mac = Mac.getInstance(hkdfAlgorithm.getMacAlgorithm().getJavaName());
                SecretKeySpec keySpec = new SecretKeySpec(prk, hkdfAlgorithm.getMacAlgorithm().getJavaName());
                mac.init(keySpec);
                ByteArrayOutputStream stream = new ByteArrayOutputStream();
                byte[] ti = new byte[0];
                int i = 1;
                while (stream.toByteArray().length < outLen) {
                    mac.update(ti);
                    mac.update(info);
                    if (Integer.toHexString(i).length() % 2 != 0) {
                        mac.update(ArrayConverter.hexStringToByteArray("0" + Integer.toHexString(i)));
                    } else {
                        mac.update(ArrayConverter.hexStringToByteArray(Integer.toHexString(i)));
                    }
                    ti = mac.doFinal();
                    if (ti.length == 0) {
                        throw new CryptoException("Could not expand HKDF. Mac Algorithm of 0 size");
                    }
                    stream.write(ti);
                    i++;
                }
                return Arrays.copyOfRange(stream.toByteArray(), 0, outLen);
            } catch (IOException | NoSuchAlgorithmException | InvalidKeyException | IllegalArgumentException ex) {
                throw new CryptoException(ex);
            }
        }


        private static byte[] labelEncoder(byte[] hashValue, String labelIn, int outLen) {
            String label = "tls13 " + labelIn;
            int labelLength = label.getBytes().length;
            int hashValueLength = hashValue.length;
            byte[] result =
                    ArrayConverter.concatenate(ArrayConverter.intToBytes(outLen, 2), ArrayConverter.intToBytes(labelLength, 1),
                            label.getBytes(), ArrayConverter.intToBytes(hashValueLength, 1), hashValue);
            return result;
        }


        public static byte[] expandLabel(HKDFAlgorithm hkdfAlgorithm, byte[] prk, String labelIn, byte[] hashValue,
                                         int outLen) throws CryptoException {
            byte[] info = labelEncoder(hashValue, labelIn, outLen);
            return expand(hkdfAlgorithm, prk, info, outLen);
        }
    }
}
