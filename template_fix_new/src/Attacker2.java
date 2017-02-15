import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import common.Config;
import static common.Utils.*;

public class Attacker2 {
	
    final private Oracle2 oracle;

    public Attacker2(Oracle2 oracle) {
        this.oracle = oracle;
    }
    
    ////////////////////////////////////////////////////////////////////////////////
    // you are allowed to add extra *private* member functions
    // however they won't be exposed to the unit tests
    // you are not allowed to add any fields
    
    /// --- start of implementation area    
    
    public byte[] crack(byte[] input) {
    	// TODO implement your crack here
    	return null;
    }
    
    /// --- end of implementation area
    ///////////////////////////////////////////////////////////////////////////////
    
    // sample test input
    // note: we internally use a JUnit like tool so this "main" function only serves as
    // a demo to show what the unit test will be like
    
    // we will use more inputs to test your implementation
    // in the unit tests, by
    // * changing Oracle2's mac key
    // * using different inputs (with different message lengths, different message patterns, etc.)
    public static void main(String[] args) {
    	//////////////////////////////////////////////////
    	// sample input tests
    	// a different key
    	String macKey = "9cdefgh!";
    	// a different input
    	byte[] input = ByteUtils.fromHexString("33a0a1a2a3a4a5a6a70f1f2f3f4f5f6f7fcff176210f519ff2d5366ae5e853491b00");
    	/////////////////////////////////////////////////
        Oracle2 oracle = new Oracle2(macKey.getBytes());
        Attacker2 attacker = new Attacker2(oracle);
        byte[] res = attacker.crack(input);
        // should be true
        System.out.println(oracle.check(input, res));
    }

}
