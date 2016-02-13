// Copyright (C) 2011 - Will Glozer.  All rights reserved.

package com.lambdaworks.crypto.test;

import com.lambdaworks.codec.Base64;
import com.lambdaworks.crypto.SCryptUtil;
import org.junit.Assert;
import org.junit.Test;
import static org.junit.Assert.*;

public class SCryptUtilTest {
    String passwd = "secret";

    @Test
    public void scrypt() {
        int N = 16384;
        int r = 8;
        int p = 1;

        String hashed = SCryptUtil.scrypt(passwd, N, r, p);
        String[] parts = hashed.split("\\$");

        assertEquals(5, parts.length);
        assertEquals("s0", parts[1]);
        Assert.assertEquals(16, Base64.decode(parts[3].toCharArray()).length);
        assertEquals(32, Base64.decode(parts[4].toCharArray()).length);

        int params = Integer.valueOf(parts[2], 16);

        assertEquals(N, (int) Math.pow(2, params >> 16 & 0xffff));
        assertEquals(r, params >> 8 & 0xff);
        assertEquals(p, params >> 0 & 0xff);
    }

    public void scryptRuby() {
        int N = 16384;
        int r = 8;
        int p = 1;

        String hashed = SCryptUtil.scryptRuby(passwd, N, r, p);
        String[] parts = hashed.split("\\$");

        assertEquals(5, parts.length);
        Assert.assertEquals(16, Base64.decode(parts[3].toCharArray()).length);
        assertEquals(32, Base64.decode(parts[4].toCharArray()).length);
        assertEquals(Integer.toString(N), parts[0]);
        assertEquals(Integer.toString(r), parts[1]);
        assertEquals(Integer.toString(p), parts[2]);
    }

    @Test
    public void check() {
        String hashed = SCryptUtil.scrypt(passwd, 16384, 8, 1);

        assertTrue(SCryptUtil.check(passwd, hashed));
        assertFalse(SCryptUtil.check("s3cr3t", hashed));

        String hashed2 = SCryptUtil.scryptRuby(passwd, 16384, 8, 1);
        assertTrue(SCryptUtil.check(passwd, hashed2));
        assertFalse(SCryptUtil.check("s3cr3t",hashed2));
    }

    @Test
    public void format_0_rp_max() throws Exception {
        int N = 2;
        int r = 255;
        int p = 255;

        String hashed = SCryptUtil.scrypt(passwd, N, r, p);
        assertTrue(SCryptUtil.check(passwd, hashed));

        String[] parts = hashed.split("\\$");
        int params = Integer.valueOf(parts[2], 16);

        assertEquals(N, (int) Math.pow(2, params >>> 16 & 0xffff));
        assertEquals(r, params >> 8 & 0xff);
        assertEquals(p, params >> 0 & 0xff);
    }
}
