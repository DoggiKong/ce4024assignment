package common;

/**
 * this file should NOT be imported by Attacker1.java
 */

public class Config {

    /// {
    // for problem 1

    // default key and suffix, will change in tests
    public static final String p1Key = "abcdefgh";
    public static final String p1Suffix = "01234567";

    // we only use DES
    public static final String ALGO = "DES";

    /// }

    //////////////////////////////////////////////////////////////////////

    /// {
    // for problem 2

    // default input string, only for reference
    public static final String p2INPUT = "00a0a1a2a3a4a5a6a70f1f2f3f4f5f6f7fcff176210f519ff2d5366ae5e853491b00";
    // default mac key, for will change in tests
    public static String p2MacKey = "abcdefgh";


    // we only use DES+CBC
    public static final String MODE = "CBC";
    public static final String DES = "DES";

    /// }

}
