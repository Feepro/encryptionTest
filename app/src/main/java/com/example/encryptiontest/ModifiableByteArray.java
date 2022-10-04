/**
 * ModifiableVariable - A Variable Concept for Runtime Modifications
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package com.example.encryptiontest;

import java.io.Serializable;
import java.util.Arrays;

public class ModifiableByteArray implements Serializable {

    public ModifiableByteArray() {
    }

    private byte[] originalValue;



    public byte[] getOriginalValue() {
        return originalValue;
    }


//    public boolean isOriginalValueModified() {
//        return originalValue != null && !Arrays.equals(originalValue, getValue());
//    }
//

//    @Override
//    public String toString() {
//        StringBuilder result = new StringBuilder();
//        if (this.isOriginalValueModified()) {
//            result.append("Actual byte value is: ");
//            result.append(ArrayConverter.bytesToHexString(this));
//            result.append("\nOriginal value was: ");
//            result.append(ArrayConverter.bytesToHexString(this.getOriginalValue()));
//        } else {
//            result.append("Original byte value is: ");
//            result.append(ArrayConverter.bytesToHexString(this.getOriginalValue()));
//        }
//        return result.toString();
//
//    }

//    @Override
//    public boolean equals(Object o) {
//        if (this == o) {
//            return true;
//        }
//        if (!(o instanceof ModifiableByteArray)) {
//            return false;
//        }
//
//        ModifiableByteArray that = (ModifiableByteArray) o;
//
//        return Arrays.equals(getValue(), that.getValue());
//    }
//
//    @Override
//    public int hashCode() {
//        int result = 17;
//        result = 31 * result + Arrays.hashCode(getValue());
//        return result;
//    }
}
