
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

        // key = 56 bits (8th bit is normally ignored) Hence should have 64bit - 8
        // input block size = 64 bits = each block contains 16 hexadecimals
        // ECB mode
        String suffix = new String();
        String builderText = "AAAAAAAAAAAAAAA";
        String plaintext = "AAAAAAAAAAAAAAAA";
        int round = 0;
        suffix = solveBlock(builderText, plaintext, suffix, 0);
        /*
        // Find first letter
        plaintext = "AAAAAAAAAAAAAAA";
        HashMap<byte[], Character> combinations = makeAllCombinations(plaintext);
        plaintext = "AAAAAAAAAAAAAAA";
        suffix = appendCharToSuffix(suffix, combinations, plaintext);

        // Second Letter
        plaintext = "AAAAAAAAAAAAAAa";
        combinations = makeAllCombinations(plaintext);
        plaintext = "AAAAAAAAAAAAAA";
        suffix = appendCharToSuffix(suffix, combinations, plaintext);

        // Third Letter
        plaintext = "AAAAAAAAAAAAAa1";
        combinations = makeAllCombinations(plaintext);
        plaintext = "AAAAAAAAAAAAA";
        suffix = appendCharToSuffix(suffix, combinations, plaintext);
        
        // Fourth Letter
        plaintext = "AAAAAAAAAAAAa19";
        combinations = makeAllCombinations(plaintext);
        plaintext = "AAAAAAAAAAAA";
        suffix = appendCharToSuffix(suffix, combinations, plaintext);
*/
        System.out.println(suffix);

        return suffix.getBytes();
    }
    
    /**
     * Each Block has 16 letters
     * 
     * Padding is 0
     * 
     * @param builderText the text to build all the combinations
     * @param plaintext the text to be appended into encryption
     * @param suffix the secret we are looking for
     * @return suffix the secret we are looking for
     */
    private String solveBlock(String builderText, String plaintext, String suffix, int round) {
        System.out.println(round + ": " + suffix);
        if (round == 16) {
            return suffix;
        }
        HashMap<byte[], Character> combinations;
        builderText = builderText.substring(0, builderText.length() - round) + suffix;
        plaintext = plaintext.substring(0, plaintext.length() - 1);
        combinations = makeAllCombinations(builderText);
        try {
            suffix = appendCharToSuffix(suffix, combinations, plaintext);
        } catch(Exception e) {
            return suffix;
        }
        
        return solveBlock(builderText, plaintext, suffix, ++round);
    }

    private HashMap<byte[], Character> makeAllCombinations(String plaintext) {
        HashMap<byte[], Character> combinations = new HashMap<byte[], Character>();
        for (int i = 0; i < 256; i++) {
            if (plaintext.length() == 16) {
                plaintext = plaintext.substring(0, plaintext.length() - 1);
            }
            plaintext = plaintext + (char) (i);
            combinations.put(oracle.compose(plaintext), (char) (i));
        }
        return combinations;
    }

    private String appendCharToSuffix(String suffix, HashMap<byte[], Character> combinations, String plaintext) throws Exception {
        for (byte[] compose : combinations.keySet()) {
            byte[] composeSection = Arrays.copyOfRange(compose, 0, 16);
            byte[] oracleSection = Arrays.copyOfRange(oracle.compose(plaintext), 0, 16);
            if (Arrays.equals(composeSection, oracleSection)) {
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
