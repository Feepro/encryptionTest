package com.example.encryptiontest

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import kotlin.experimental.and
import kotlin.experimental.xor

//cipher_mode GCRY_CIPHER_MODE_GCM
//cipher_algo GCRY_CIPHER_AES128
/*
 * initial_salt = 0xafbfec289993d24c9e9786f19c6111e04390a899
 * initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
 *
 * client_initial_secret = HKDF-Expand-Label(initial_secret,
 * "client in", "", Hash.length)
 * server_initial_secret = HKDF-Expand-Label(initial_secret,
 * "server in", "", Hash.length)
 *
 * Hash for handshake packets is SHA-256 (output size 32).
 */
//version = tvb_get_ntohl(tvb, offset);
/*/* Returns the QUIC draft version or 0 if not applicable. */
static inline guint8 quic_draft_version(guint32 version) {
/* IETF Draft versions */
if ((version >> 8) == 0xff0000) {
 return (guint8) version;
}
/* Facebook mvfst, based on draft -22. */
if (version == 0xfaceb001) {
return 22;
}
/* Facebook mvfst, based on draft -27. */
if (version == 0xfaceb002 || version == 0xfaceb00e) {
return 27;
}
/* GQUIC Q050, T050 and T051: they are not really based on any drafts,
 * but we must return a sensible value */
if (version == 0x51303530 ||
version == 0x54303530 ||
version == 0x54303531) {
return 27;
}
/* https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-15
 "Versions that follow the pattern 0x?a?a?a?a are reserved for use in
 forcing version negotiation to be exercised"
 It is tricky to return a correct draft version: such number is primarily
 used to select a proper salt (which depends on the version itself), but
 we don't have a real version here! Let's hope that we need to handle
 only latest drafts... */
if ((version & 0x0F0F0F0F) == 0x0a0a0a0a) {
return 29;
}
/* QUIC (final?) constants for v1 are defined in draft-33, but draft-34 is the
 final draft version */
if (version == 0x00000001) {
return 34;
}
/* QUIC Version 2 */
/* TODO: for the time being use 100 as a number for V2 and let
 see how v2 drafts evolve */
if (version == 0x709A50C4) {
 return 100;
}
return 0;
}*/

val connectionId = "f38707e5a235e970".decodeHex()
val payload = "420e9cf6533f4fd6068a02e27b9d39910a68088f8a64add412d97076c716b85e36187e55a16ddc03a74e2db953ba8da33510f132b7ee17e499e40638cb96e82485803791fd86b8978fcca5ace7a708ccb61e0f8af8fe8c83a871f473ccb0eb42d73accb6bf37a129fc4eb3fe27391326275bcfb2b1f3a69bdfbbfbe6ed189455e8ac112e8215461f55f917663e308b04eaaaff83c6eefc7c2b08f47eeb3e64bb7c11a20922f1bbb8a95259be67b437f9c34c068db53423a66363f1d376bfa206ed54b35681c4eaf2dac101a5cbac9de4345602f043cdd90b3ca4e996ee3c5aaf6af9d7fa6f7797fd64740572b5943d17dae36daa83ed3bd374bc584b5100260d4f7c76953407c7c0b8dfe7cc23f446e55041966f0e276a303884f1e14df7ba0f58222833e680b51475484d0141eb82131194e1917ced3e0758331c13b62988ce7c430381b48deb2a344134824b539e79baf9b616d7ce8538572985a50dbc92e44c13a8cde64901b08b8004612b1c3b5802580812643538c44ec5efcb7d45898188b40d16ade37711fc574c6c137640f1d4459b1b7d4efb3fea924199547e3acb961dc8029718517d860f978b7805d8e5334901a4059272553c5cf80d77d156e6629d355b908df3d9559aa6d4bfb63b967f3dd9e09617db20d58dc1947c2e1b136f87635df0252061e0760be7bf28fd9ed08fc93e9c2364ced294670c09ed3cffedf4c033011650c936d1e0440cc5951a38cf11a809f570292583cb5151747df45e5711e93dd8cb9327669c062ec563d15a99df600c409b79dc288a063c92c9cdb5d25978882e5c1448fb0279bff088d0cfe03022800bb8265d1b3ad87f8dad89d95cfb1e2c6885c6a58c28f850c783b42ba83442788b993d1d04e0381e309542f25cf6193cc78e2db7316eaf37b33dfa84e98d91c7aa879cd2cab0eeee6033bb9d3f3490a69d93a482b48a47f5fcad983eea03a60a05f61a59796ade38d1a93006fcde73e81d4f9d7deeea2750b60e734562cd2931eab318b4ced77dc18d32093ba04513160cb327b2a08a96b054cb131b6a91eff8b14f205ad2d5a21b302e5e905e785508597658b0a18f3387d3a065ea7387c463933060794bef3121caedeb95425859333c17b1cc83d2f9f02f028ae3fc1fca06e4be880c16303cc4f930dfad43097435940b4fbedaae1225773163d1b6b632437253bdc03e52492ec5fc90013660eb905fbb5266e41f4821caaa9870ef06ff46c533785053293d85df991442acb934c50ec839309fbcb5199602ea54e6962916217ef8c495cc1966716f8002ca6c2413664c3b6d4332851e23aea85023ce1069649202b02c0216d41a7bb37a2ec7b7ec2d9951b618371e4fdfb8dd12da7d5942087ed6dfe83c7831def486ab906db1ecf7717f0de355b4fe1b3380f690ab7e04a6313c5e757afaefd2d785bb8b99dbccbd7c9b5760a31f417065a7fccb131afbbb55fa440b53edb657a3a5b62c2edef2e15556ff3b8a16fa6ea08eef46d9ff3cb61b8ea26ee8230b3668ed138eab79a1caa64a0f3c59b2d035689525903fd1e535f3e3a3ff78dfb247e7774f6e708f1c72ef193dda8936c16af09aa1c89571fcefcbfba31933f15b8405593d8ddec09d9517225c6d8aefbd82be4d688e9d83385f1db6e57af8057248e0ffc65a52721fde5ad42b0a7344536d5317bbb6c293f18da79c728a65b5df1d12647332f9982d9d8ab69e9b7b800fa032".decodeHex()
val fullPacket = "00450004fe7d97400080110000c0a82b02adc2de5deb6501bb04ea7cc6c00000000108f38707e5a235e970000044d007420e9cf6533f4fd6068a02e27b9d39910a68088f8a64add412d97076c716b85e36187e55a16ddc03a74e2db953ba8da33510f132b7ee17e499e40638cb96e82485803791fd86b8978fcca5ace7a708ccb61e0f8af8fe8c83a871f473ccb0eb42d73accb6bf37a129fc4eb3fe27391326275bcfb2b1f3a69bdfbbfbe6ed189455e8ac112e8215461f55f917663e308b04eaaaff83c6eefc7c2b08f47eeb3e64bb7c11a20922f1bbb8a95259be67b437f9c34c068db53423a66363f1d376bfa206ed54b35681c4eaf2dac101a5cbac9de4345602f043cdd90b3ca4e996ee3c5aaf6af9d7fa6f7797fd64740572b5943d17dae36daa83ed3bd374bc584b5100260d4f7c76953407c7c0b8dfe7cc23f446e55041966f0e276a303884f1e14df7ba0f58222833e680b51475484d0141eb82131194e1917ced3e0758331c13b62988ce7c430381b48deb2a344134824b539e79baf9b616d7ce8538572985a50dbc92e44c13a8cde64901b08b8004612b1c3b5802580812643538c44ec5efcb7d45898188b40d16ade37711fc574c6c137640f1d4459b1b7d4efb3fea924199547e3acb961dc8029718517d860f978b7805d8e5334901a4059272553c5cf80d77d156e6629d355b908df3d9559aa6d4bfb63b967f3dd9e09617db20d58dc1947c2e1b136f87635df0252061e0760be7bf28fd9ed08fc93e9c2364ced294670c09ed3cffedf4c033011650c936d1e0440cc5951a38cf11a809f570292583cb5151747df45e5711e93dd8cb9327669c062ec563d15a99df600c409b79dc288a063c92c9cdb5d25978882e5c1448fb0279bff088d0cfe03022800bb8265d1b3ad87f8dad89d95cfb1e2c6885c6a58c28f850c783b42ba83442788b993d1d04e0381e309542f25cf6193cc78e2db7316eaf37b33dfa84e98d91c7aa879cd2cab0eeee6033bb9d3f3490a69d93a482b48a47f5fcad983eea03a60a05f61a59796ade38d1a93006fcde73e81d4f9d7deeea2750b60e734562cd2931eab318b4ced77dc18d32093ba04513160cb327b2a08a96b054cb131b6a91eff8b14f205ad2d5a21b302e5e905e785508597658b0a18f3387d3a065ea7387c463933060794bef3121caedeb95425859333c17b1cc83d2f9f02f028ae3fc1fca06e4be880c16303cc4f930dfad43097435940b4fbedaae1225773163d1b6b632437253bdc03e52492ec5fc90013660eb905fbb5266e41f4821caaa9870ef06ff46c533785053293d85df991442acb934c50ec839309fbcb5199602ea54e6962916217ef8c495cc1966716f8002ca6c2413664c3b6d4332851e23aea85023ce1069649202b02c0216d41a7bb37a2ec7b7ec2d9951b618371e4fdfb8dd12da7d5942087ed6dfe83c7831def486ab906db1ecf7717f0de355b4fe1b3380f690ab7e04a6313c5e757afaefd2d785bb8b99dbccbd7c9b5760a31f417065a7fccb131afbbb55fa440b53edb657a3a5b62c2edef2e15556ff3b8a16fa6ea08eef46d9ff3cb61b8ea26ee8230b3668ed138eab79a1caa64a0f3c59b2d035689525903fd1e535f3e3a3ff78dfb247e7774f6e708f1c72ef193dda8936c16af09aa1c89571fcefcbfba31933f15b8405593d8ddec09d9517225c6d8aefbd82be4d688e9d83385f1db6e57af8057248e0ffc65a52721fde5ad42b0a7344536d5317bbb6c293f18da79c728a65b5df1d12647332f9982d9d8ab69e9b7b800fa032".decodeHex()
val associatedData = "c00000000108f38707e5a235e970000044d007".decodeHex()
val sample = "533f4fd6068a02e27b9d39910a68088f".decodeHex()
class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val packetProtectionImpl = InitialPacketProtectionImpl()
        packetProtectionImpl.initialize(connectionId)
        val nonce = packetProtectionImpl.deriveAeadNonce(1)

        val mask = packetProtectionImpl.deriveHeaderProtectionMask(sample,0, sample.size)

        // "The least significant
        //   bits of the first byte of the packet [that is, the flags] are masked by the least
        //   significant bits of the first mask byte..." QUIC Spec-TLS/Section 5.4.1
        val decryptedFlags: Byte = (0xc0.toByte().xor(mask.get(0)).and(15)).toByte()

        val unprotectedPacketNumberLength: Int = 1// call may be inlined? //FROM FLAG

        val protectedPacketNumber = ByteArray(unprotectedPacketNumberLength)
        protectedPacketNumber[0] = 0x07

        // "[...] and the packet number is
        //   masked with the remaining bytes.  Any unused bytes of mask that might
        //   result from a shorter packet number encoding are unused." QUIC Spec-TLS/Section 5.4.1
        for (i in 0 until unprotectedPacketNumberLength) {
            protectedPacketNumber[i] = protectedPacketNumber[i] xor mask.get(1 + i)
        }
        // and overwrite that with the unprotected parts
        System.arraycopy(
            protectedPacketNumber /*which is now unprotected*/, 0, associatedData,
            associatedData.size - protectedPacketNumber.size, protectedPacketNumber.size
        )
        associatedData[0] = decryptedFlags

        val decryptedPayload = packetProtectionImpl.aeadDecrypt(payload, associatedData,nonce)
        val decryptToStr = decryptedPayload.toString(charset("UTF-8"))
    }
}



fun String.decodeHex(): ByteArray {
    check(length % 2 == 0) { "Must have an even length" }

    return chunked(2)
        .map { it.toInt(16).toByte() }
        .toByteArray()
}


