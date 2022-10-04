
package com.example.encryptiontest;


public class ArrayConverter {


    public static byte[] intToBytes(int value, int size) {
        if (size < 1) {
            throw new IllegalArgumentException("The array must be at least of size 1");
        }
        byte[] result = new byte[size];
        int shift = 0;
        int finalPosition = ((size > Integer.BYTES) ? (size - Integer.BYTES) : 0);
        for (int i = size - 1; i >= finalPosition; i--) {
            result[i] = (byte) (value >>> shift);
            shift += 8;
        }

        return result;
    }


    public static String bytesToHexString(byte[] array) {
        if (array == null) {
            array = new byte[0];
        }
        boolean usePrettyPrinting = (array.length > 15);
        return bytesToHexString(array, usePrettyPrinting);
    }

    public static String bytesToHexString(byte[] array, boolean usePrettyPrinting) {
        if (array == null) {
            array = new byte[0];
        }
        return bytesToHexString(array, usePrettyPrinting, true);
    }

    public static String bytesToHexString(byte[] array, boolean usePrettyPrinting, boolean initialNewLine) {
        StringBuilder result = new StringBuilder();
        if (initialNewLine && usePrettyPrinting) {
            result.append("\n");
        }
        for (int i = 0; i < array.length; i++) {
            if (i != 0) {
                if (usePrettyPrinting && (i % 16 == 0)) {
                    result.append("\n");
                } else {
                    if (usePrettyPrinting && (i % 8 == 0)) {
                        result.append(" ");
                    }
                    result.append(" ");
                }
            }
            byte b = array[i];
            result.append(String.format("%02X", b));
        }
        return result.toString();
    }


    public static byte[] concatenate(final byte[]... arrays) {
        if (arrays == null || arrays.length == 0) {
            throw new IllegalArgumentException("The minimal number of parameters for this function is one");
        }
        int length = 0;
        for (final byte[] a : arrays) {
            if (a != null) {
                length += a.length;
            }
        }
        byte[] result = new byte[length];
        int currentOffset = 0;
        for (final byte[] a : arrays) {
            if (a != null) {
                System.arraycopy(a, 0, result, currentOffset, a.length);
                currentOffset += a.length;
            }
        }
        return result;
    }

    public static byte[] hexStringToByteArray(String input) {
        if ((input == null) || (input.length() % 2 != 0)) {
            throw new IllegalArgumentException("The input must not be null and "
                + "shall have an even number of hexadecimal characters. Found: " + input);
        }
        byte[] output = new byte[input.length() / 2];
        for (int i = 0; i < output.length; i++) {
            output[i] =
                (byte) ((Character.digit(input.charAt(i * 2), 16) << 4) + Character.digit(input.charAt(i * 2 + 1), 16));
        }
        return output;
    }


}
