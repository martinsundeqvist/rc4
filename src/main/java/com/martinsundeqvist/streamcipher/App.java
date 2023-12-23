package com.martinsundeqvist.streamcipher;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

public class App 
{
    public static final int KEY_LENGTH = 256;

    static class Utils {
        public static void swap(int[] arr, int i, int j) {
            int temp = arr[i];
            arr[i] = arr[j];
            arr[j] = temp;
        }
    }

    static class Rc4Cipher {

        private int[] key;
        private int keyLength;

        public Rc4Cipher(int[] key, int keyLength) {
            this.key = key;
            this.keyLength = keyLength;
        }

        public int[] stateArray() {
            // Note consistent usage of "int" over byte. byte is bounded -128 <= b <= 127
            // we need unsigned byte 0 <= b <= 255.
            int[] s = new int[256];
            // Initialize the original permutation of s (s[0] = 0, s[1] = 1, ..., s[255] = 255)
            for (int i = 0; i < 256; i++) {
                s[i] = i;
            }

            int j = 0;
            for (int i = 0; i < 256; i++) {
                j = (j + s[i] + this.key[i % this.keyLength]) % 256;
                int temp = s[i];
                s[i] = s[j];
                s[j] = temp;
            }

            return s;
        }
        
        // Generates a pseudo-random keystream to be used in plaintext encryption
        public int[] pseudoRandomNumberGenerator(int[] s, int plaintextLength) {
            int i = 0;
            int j = 0;
            int[] k = new int[plaintextLength];
            for (int x = 0; x < plaintextLength; x++) {
                i = (i + 1) % 256;
                j = (j + s[i]) % 256;
                App.Utils.swap(s, i, j);
                int t = (s[i] + s[j]) % 256;
                k[x] = s[t];
            }
            return k;
        }
    }

    public static void main(String[] args )
    {
        String plaintext = args[0];
        
        // Initialize the key with random bytes to the desired key length using a "secure" random implementation
        int[] key = new int[KEY_LENGTH];
        SecureRandom secureRandom = new SecureRandom();
        for (int i = 0; i < KEY_LENGTH; i ++) {
            // We give keyLength as the upper bound to the nextInt() to make sure 0 <= keyvalue < keyLength
            key[i] = secureRandom.nextInt(KEY_LENGTH);
        }

        Rc4Cipher cipher = new App.Rc4Cipher(key, KEY_LENGTH);
        int[] s = cipher.stateArray();

        byte[] plaintextBytes = plaintext.getBytes();
        int[] keystream = cipher.pseudoRandomNumberGenerator(s, plaintextBytes.length);

        int[] encryptedData = new int[plaintextBytes.length];
        for (int i = 0 ; i < plaintextBytes.length; i ++) {
            encryptedData[i] = ((int) plaintextBytes[i] & 0xFF) ^ keystream[i];
        }

        byte[] decryptedBytes = new byte[encryptedData.length];
        for (int i = 0; i < encryptedData.length; i++) {
            decryptedBytes[i] = (byte)(encryptedData[i] ^ keystream[i]);
        }

        String decryptedText = new String(decryptedBytes, StandardCharsets.UTF_8);
        
        System.out.println("Plaintext: " + plaintext);
        System.out.println("Decrypted text: " + decryptedText);


    }
}
