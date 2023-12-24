package com.martinsundeqvist.streamcipher;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.martinsundeqvist.streamcipher.App.Rc4Cipher;

public class AppTest 
{
    @Test
    public void HELLOWORLD_encodes_correctly()
    {
        int[] key = new int[] {1, 2, 3, 4, 5, 6, 7, 8};
        byte[] plaintextBytes = "HELLOWORLD".getBytes();
        Rc4Cipher cipher = new Rc4Cipher(key, key.length);

        cipher.ksa();

        int[] s = cipher.ksa();

        int[] keystream = cipher.prng(s, plaintextBytes.length);

        int[] encryptedData = cipher.encrypt(plaintextBytes, keystream);
        int[] expectedData = new int[] {223, 238, 198, 87, 191, 248, 246, 51, 126, 182};

        assertEquals(encryptedData.length, expectedData.length);
        for (int i = 0; i < encryptedData.length; i++)
            assertEquals(encryptedData[i], expectedData[i]);

    }
}
