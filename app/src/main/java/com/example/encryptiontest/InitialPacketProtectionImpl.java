package com.example.encryptiontest;


import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import at.favre.lib.crypto.HKDF;

public class InitialPacketProtectionImpl {

    /**
     * The initial salt is a meaningless truly random number defined by the protocol authors.
     *
     * @see <a href="https://github.com/quicwg/base-drafts/issues/4325">Github Issue of QUIC Working Group about the
     * arbitrary nature of that salt</a>
     * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-tls-32#section-5.2">QUIC Spec-TLS/Section 5.2</a>
     */
    public static final byte[] INITIAL_SALT = new byte[]{
            (byte)0xaf, (byte)0xbf, (byte)0xec, (byte)0x28, (byte)0x99, (byte)0x93, (byte)0xd2, (byte)0x4c,
            (byte)0x9e, (byte)0x97, (byte)0x86, (byte)0xf1, (byte)0x9c, (byte)0x61, (byte)0x11, (byte)0xe0,
            (byte)0x43, (byte)0x90, (byte)0xa8, (byte)0x99
    };

    /**
     * The hash function for HKDF when deriving initial secrets and keys is SHA-256 [SHA].
     *
     * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-tls-32#section-5.2">QUIC Spec-TLS/Section 5.2</a>
     */
    public static final HKDF INITIAL_DERIVATION_FUNCTION = HKDF.fromHmacSha256();

    private byte[] clientInitialSecret;
    private byte[] serverInitialSecret;
    private byte[] clientInitialKey;
    private byte[] clientInitialIV;
    private byte[] headerProtectionSecret;
    private Cipher headerProtectionCipher;

    /**
     * Generates the initial_secret as described by the pseudo-code of Section 5.2
     *
     * @param clientDestinationConnectionId the pseudo-code-parameter client_dst_connection_id
     * @return the pseudo-code-result initial_secret
     */
    public static byte[] extractInitialSecret( byte[] clientDestinationConnectionId ) {
        return INITIAL_DERIVATION_FUNCTION.extract( INITIAL_SALT, clientDestinationConnectionId );
    }

    /**
     * Generates the client_initial_secret as described by the pseudo-code of Section 5.2
     *
     * @param initialSecret the pseudo-code-parameter initial_secret
     * @return the pseudo-code-result client_initial_secret
     */
    public static byte[] expandInitialClientSecret(  byte[] initialSecret ) {
        return HkdfUtil.tlsExpandLabel( INITIAL_DERIVATION_FUNCTION,
                initialSecret, HkdfUtil.LABEL_CLIENT_IN, null, ( 256 / 8 ) /*sha 256 byte length*/ );
    }

    /**
     * Generates the server_initial_secret as described by the pseudo-code of Section 5.2
     *
     * @param initialSecret the pseudo-code-parameter initial_secret
     * @return the pseudo-code-result server_initial_secret
     */
    public static byte[] expandInitialServerSecret(  byte[] initialSecret ) {
        return HkdfUtil.tlsExpandLabel( INITIAL_DERIVATION_FUNCTION,
                initialSecret, HkdfUtil.LABEL_SERVER_IN, null, ( 256 / 8 ) /*sha 256 byte length*/ );
    }

    public static byte[] expandInitialHeaderProtection(  byte[] initialSecret ) {
        return HkdfUtil.tlsExpandLabel( INITIAL_DERIVATION_FUNCTION,
                initialSecret, HkdfUtil.LABEL_QUIC_HP, null, 16 /* header protection mask byte length */ );
    }

    public static byte[] expandInitialQuicKey(  byte[] initialSecret ) {
        return HkdfUtil.tlsExpandLabel( INITIAL_DERIVATION_FUNCTION,
                initialSecret, HkdfUtil.LABEL_QUIC_KEY, null, ( 128 / 8 ) );
    }

    public static byte[] expandInitialQuicIv(  byte[] initialSecret ) {
        return HkdfUtil.tlsExpandLabel( INITIAL_DERIVATION_FUNCTION,
                initialSecret, HkdfUtil.LABEL_QUIC_IV, null, ( 96 / 8 ) );
    }

    /**
     * Computes all initial secrets for server, client and header protection
     *
     * @param clientDestinationConnectionId the destination connection id sent by the client
     *                                      in the { InitialPacketImpl}
     * @throws NoSuchPaddingException   if the spec-required cipher could not be initialized
     * @throws NoSuchAlgorithmException if the spec-required cipher could not be initialized
     * @throws InvalidKeyException      if the spec-required cipher could not be initialized
     */
    public void initialize(  byte[] clientDestinationConnectionId )
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        byte[] initialSecret = extractInitialSecret( clientDestinationConnectionId );
        clientInitialSecret = expandInitialClientSecret( initialSecret );
        serverInitialSecret = expandInitialServerSecret( initialSecret );
        clientInitialKey = expandInitialQuicKey( clientInitialSecret );
        clientInitialIV = expandInitialQuicIv( clientInitialSecret );
        headerProtectionSecret = expandInitialHeaderProtection( clientInitialSecret );
        // https://tools.ietf.org/html/draft-ietf-quic-tls-27#section-5.4.3
        // "AEAD_AES_128_GCM and AEAD_AES_128_CCM use 128-bit AES [AES] in electronic code-book (ECB) mode."
        headerProtectionCipher = Cipher.getInstance( "AES/ECB/NoPadding" );
        SecretKeySpec keySpec = new SecretKeySpec( headerProtectionSecret, "AES" );
        headerProtectionCipher.init( Cipher.ENCRYPT_MODE, keySpec );
    }

    public byte[] deriveHeaderProtectionMask(  byte[] sample, int offset, int length ) {
        if ( headerProtectionCipher == null ) {
            return null;
        }
        try {
            return headerProtectionCipher.doFinal( sample, offset, length );
        }
        catch ( IllegalBlockSizeException | BadPaddingException e ) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Derives the 16 bytes nonce used as a {@link GCMParameterSpec GCM Parameter} for AEAD_AES_128_GCM.
     * <p/>
     * "The nonce, N, is formed by combining the packet
     * protection IV with the packet number. The 62 bits of the
     * reconstructed QUIC packet number in network byte order are left-
     * padded with zeros to the size of the IV. The exclusive OR of the
     * padded packet number and the IV forms the AEAD nonce."
     * Quote from
     * <a href="https://tools.ietf.org/html/draft-ietf-quic-tls-32#section-5.3">QUIC Spec-TLS/Section 5.3</a>
     *
     * @param packetNumber the packet number to combine with the input vector
     * @return the nonce for AEAD_AES_128_GCM, never null, always 16 bytes length
     */
    public byte[] deriveAeadNonce( long packetNumber ) {
        byte[] nonce = new byte[12]; // java arrays are prefilled with 0
        VariableLengthIntegerEncoder.encodeFixedLengthInteger( packetNumber, nonce, 4, 8 );
        for ( int i = 0; i < nonce.length; i++ ) {
            nonce[i] ^= clientInitialIV[i];
        }
        return nonce;
    }

    /**
     * Performs AEAD_AES_128_GCM decryption using this {@link #clientInitialKey}.
     * <p/>
     * "Initial packets use AEAD_AES_128_GCM with keys derived from the
     * Destination Connection ID field of the first Initial packet sent
     * by the client; see Section 5.2."
     * Quote from
     * <a href="https://tools.ietf.org/html/draft-ietf-quic-tls-32#section-5">QUIC Spec-TLS/Section 5</a>
     *
     * Hint: all exceptions thrown by this method are of subtypes of {@link GeneralSecurityException}
     *
     * @param message        the ciphertext to decrypt
     * @param associatedData the associated data (in QUIC: the unprotected packet header including the unprotected
     *                       packet number)
     * @param nonce          the nonce derived from the packet number (see {@link #deriveAeadNonce(long)})
     * @return the decrypted ciphertext, thus the plaintext of the message
     * @throws BadPaddingException                if decryption somehow fails
     * @throws NoSuchPaddingException             if decryption somehow fails
     * @throws IllegalBlockSizeException          if decryption somehow fails
     * @throws InvalidAlgorithmParameterException if decryption somehow fails
     * @throws InvalidKeyException                if decryption somehow fails
     * @throws NoSuchAlgorithmException           if decryption somehow fails
     */
    public byte[] aeadDecrypt( byte[] message, byte[] associatedData, byte[] nonce )
            throws BadPaddingException, IllegalBlockSizeException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher aeadCipher = Cipher.getInstance( "AES/GCM/NoPadding" );
        SecretKeySpec secretKey = new SecretKeySpec( clientInitialKey, "AES" );

        GCMParameterSpec parameterSpec = new GCMParameterSpec( 128 /* AEAD_AES_128_GCM */, nonce );

        aeadCipher.init( Cipher.DECRYPT_MODE, secretKey, parameterSpec );
        aeadCipher.updateAAD( associatedData );
        return aeadCipher.doFinal( message );
    }

}
