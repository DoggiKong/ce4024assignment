
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import common.Config;
import static common.Utils.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;

public class Attacker1 {

    final private Oracle1 oracle;

    public Attacker1() {
        this.oracle = new Oracle1();
    }

    public Attacker1(Oracle1 oracle) {
        this.oracle = oracle;
    }

    ////////////////////////////////////////////////////////////////////////////////
    // you are allowed to add extra *private* member functions
    // however they won't be exposed to the unit tests
    // you are not allowed to add any fields
    /// --- start of implementation area
    public byte[] decryptSuffix() {
        // TODO implement decryption code here
        String suffix = new String();
        int block = 0;
        String builderText = makeText((block * 16 + 16 - 1));
        String plaintext = makeText((block * 16 + 16));
        int round = 0;
        while (true) {
            if (round == (16 * block + 16)) {
                block++;
                builderText = makeText((block * 16 + 16 - 1));
                plaintext = makeText((block * 16 + 16));
                round = 0;
                continue;
            }
            HashMap<byte[], Character> combinations;
            builderText = builderText.substring(0, builderText.length() - round) + suffix.substring(0, round);
            plaintext = plaintext.substring(0, plaintext.length() - 1);
            combinations = makeAllCombinations(builderText, block);
            try {
                if (16 * block + 15 - round < 16) {
                    suffix = appendCharToSuffix(suffix, combinations, plaintext, block);
                } else {
                    round = 16 * block- 1;
                    builderText = makeText(16) + suffix.substring(0, suffix.length() - 1);
                    plaintext = makeText(16);
                }
            } catch (Exception e) {
                break;
            }
            round++;
        }
        return suffix.getBytes();
    }

    private String makeText(int n) {
        return new String(new char[n]).replace("\0", "A");
    }

    private HashMap<byte[], Character> makeAllCombinations(String plaintext, int block) {
        HashMap<byte[], Character> combinations = new HashMap<byte[], Character>();
        for (int i = 0; i < 256; i++) {
            if (plaintext.length() == (block * 16 + 16)) {
                plaintext = plaintext.substring(0, plaintext.length() - 1);
            }
            plaintext = plaintext + (char) (i);
            combinations.put(oracle.compose(plaintext), (char) (i));
        }
        return combinations;
    }

    private String appendCharToSuffix(String suffix, HashMap<byte[], Character> combinations, String plaintext, int block) throws Exception {
        for (byte[] compose : combinations.keySet()) {
            byte[] composeSection = Arrays.copyOfRange(compose, block * 16, block * 16 + 16);
            byte[] oracleSection = Arrays.copyOfRange(oracle.compose(plaintext), block * 16, block * 16 + 16);
            if (Arrays.equals(composeSection, oracleSection)) {
                if (combinations.get(compose) == 0) {
                    throw new Exception();
                }
                return suffix + combinations.get(compose);
            }
        }
        throw new Exception();
    }

    /// --- end of implementation area
    ////////////////////////////////////////////////////////////////////////////////
    // sample test input
    // note: we internally use a JUnit like tool so this "main" function only serves as
    // a demo to show what the unit test will be like
    // we will use more inputs to test your implementation
    // in the unit tests, by
    // * changing Oracle1's key
    // * changing Oracle1's suffix
    public static void main(String[] args) {
        ///////////////////////////////////////////////////////////
        String key = "3%ac^`+=";  // a different key
        String suffix = "a19q-j*"; // a different suffix
        ///////////////////////////////////////////////////////////
        Oracle1 oracle = new Oracle1(key.getBytes(), suffix.getBytes());
        Attacker1 attacker = new Attacker1(oracle);
        byte[] res = attacker.decryptSuffix();
        ///////////////////////////////////////////////////////////
        // should be true
        System.out.println(isConsistent(suffix, res));
    }

}
