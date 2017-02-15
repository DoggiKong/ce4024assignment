package common;

import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


@SuppressWarnings({"WeakerAccess", "ForLoopReplaceableByForEach", "SameParameterValue"})
public class Utils {

    public static String dumpListsOfBytes(List<byte[]> oList) {
        StringBuilder sb = new StringBuilder();
        sb.append("\n======================\n");
        for (byte[] bytes : oList) {
            sb.append(ppBytes(bytes)).append("\n");
        }
        sb.append("======================");
        return sb.toString();
    }

    public static boolean isConsistent(byte[] given, byte[] computed) {
    	require(given!=null, "given is never null");
    	if(computed==null) return false;
        if (given.length > computed.length) return false;
        for (int i = 0; i < given.length; ++i) {
            if (given[i] != computed[i]) {
                return false;
            }
        }
        return true;
    }

    public static boolean isConsistent(String given, byte[] computed) {
        return isConsistent(given.getBytes(), computed);
    }

    public static void require(boolean cond, String msg) {
        if (!cond) {
            throw new IllegalArgumentException(msg);
        }
    }

    public static String ppBytes(byte[] bytes) {
        StringBuilder sb = new StringBuilder("[ ");
        for (byte b : bytes) {
            sb.append(String.format("0x%02x ", b));
        }
        sb.append("]");
        return sb.toString();
    }

    private static Map<String, Integer> algoSizePair = new HashMap<String, Integer>();

    static {
        algoSizePair.put("DES", 8);
        algoSizePair.put("AES", 16);
    }

    public static int getAlgoBlockSize(String algo) {
        return algoSizePair.get(algo);
    }

    public static boolean isSizeLegal(byte[] key, String algorithm) {
        return getAlgoBlockSize(algorithm) == key.length;
    }

    public static byte[] concat(byte[] first, byte single) {
        byte[] singleton = new byte[]{single};
        return concat(first, singleton);
    }

    public static byte[] concat(byte[] first, byte[] second) {
        byte[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    public static byte[] safeXor(byte[] b1, byte[] b2) {
        int l1 = b1.length;
        int l2 = b2.length;
        if (l1 == l2) {
            return ByteUtils.xor(b1, b2);
        } else if (l1 > l2) {
            // truncate l1
            byte[] n1 = Arrays.copyOfRange(b1, l1 - l2, l1);
            return ByteUtils.xor(n1, b2);
        } else {
            // truncate l2
            byte[] n2 = Arrays.copyOfRange(b2, l2 - l1, l2);
            return ByteUtils.xor(b1, n2);
        }
    }

    public static byte[] prependZeros(byte[] bytes, int num) {
        byte[] zeros = new byte[num];
        return concat(zeros, bytes);
    }

    public static byte[] extXor(byte[] b1, byte[] b2) {
        int l1 = b1.length;
        int l2 = b2.length;
        if (l1 == l2) {
            return ByteUtils.xor(b1, b2);
        } else if (l1 > l2) {
            byte[] n2 = prependZeros(b2, l1 - l2);
            return ByteUtils.xor(b1, n2);
        } else {
            byte[] n1 = prependZeros(b1, l2 - l1);
            return ByteUtils.xor(n1, b2);
        }
    }

    public static byte[] paddingBytes(byte[] input, int blockSize) {
        int paddingSize = (blockSize - (input.length % blockSize)) % blockSize;
        byte[] padding = new byte[paddingSize];
        return concat(input, padding);
    }

}
