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

        public int[] ksa() {
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
        public int[] prng(int[] s, int plaintextLength) {
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

        public int[] encrypt(byte[] plaintextBytes, int[] keystream) {
            // For consistency w. state array and keystream we convert from signed bytes [-128, 127]
            // to unsigned bytes [0, 255] represented as integers.
            int[] plaintextUnsignedBytes = new int[plaintextBytes.length];
            for (int i = 0; i < plaintextBytes.length; i++) {
                plaintextUnsignedBytes[i] = plaintextBytes[i] & 0xFF;
            }

            // XOR the plaintext bytes with the keystream to get the ciphertext
            int[] encryptedData = new int[plaintextUnsignedBytes.length];
            for (int i = 0 ; i < plaintextUnsignedBytes.length; i ++) {
                encryptedData[i] = plaintextUnsignedBytes[i] ^ keystream[i];
            }
            return encryptedData;
        }

        public String decrypt(int[] encryptedData, int[] keystream) {
            // XOR the ciphertext bytes with the keystream to decrypt back to plaintext
            int[] decryptedData = new int [encryptedData.length];
            for (int i = 0 ; i < encryptedData.length; i ++) {
                decryptedData[i] = encryptedData[i] ^ keystream[i];
            }

            byte[] decryptedBytes = new byte[decryptedData.length];
            for (int i = 0; i < decryptedData.length; i++) {
                // Casting to byte gets rid of all higher-order bits (i.e. anything past fist 8 bits)
                // since byte is a signed type we "wrap around": if decryptedData[i] == 128 then decryptedBytes[i] = -128
                decryptedBytes[i] = (byte)decryptedData[i];
            }

            return new String(decryptedBytes, StandardCharsets.UTF_8);
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

        byte[] plaintextBytes = plaintext.getBytes();

        Rc4Cipher cipher = new App.Rc4Cipher(key, KEY_LENGTH);
        
        int[] s = cipher.ksa();

        int[] keystream = cipher.prng(s, plaintextBytes.length);

        int[] encryptedData = cipher.encrypt(plaintextBytes, keystream);

        String decryptedText = cipher.decrypt(encryptedData, keystream);
        
        System.out.println("Plaintext: " + plaintext);
        System.out.print("Encrypted data: ");
        for (int i = 0; i < encryptedData.length; i++) {
            System.out.print(String.format("%02X ", encryptedData[i]));
        }
        System.out.println();
        System.out.println("Decrypted ciphertext: " + decryptedText);

    }
}
