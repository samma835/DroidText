package repack.org.bouncycastle.jce.provider.symmetric;

import java.util.HashMap;

import repack.org.bouncycastle.crypto.CipherKeyGenerator;
import repack.org.bouncycastle.crypto.engines.HC256Engine;
import repack.org.bouncycastle.jce.provider.JCEKeyGenerator;
import repack.org.bouncycastle.jce.provider.JCEStreamCipher;

public final class HC256
{
    private HC256()
    {
    }
    
    public static class Base
        extends JCEStreamCipher
    {
        public Base()
        {
            super(new HC256Engine(), 32);
        }
    }

    public static class KeyGen
        extends JCEKeyGenerator
    {
        public KeyGen()
        {
            super("HC256", 256, new CipherKeyGenerator());
        }
    }

    public static class Mappings
        extends HashMap
    {
        public Mappings()
        {
            put("Cipher.HC256", "org.bouncycastle.jce.provider.symmetric.HC256$Base");
            put("KeyGenerator.HC256", "org.bouncycastle.jce.provider.symmetric.HC256$KeyGen");
        }
    }
}
