package repack.org.bouncycastle.jce.provider.asymmetric.ec;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import repack.org.bouncycastle.asn1.ASN1EncodableVector;
import repack.org.bouncycastle.asn1.ASN1InputStream;
import repack.org.bouncycastle.asn1.ASN1Sequence;
import repack.org.bouncycastle.asn1.DERInteger;
import repack.org.bouncycastle.asn1.DEROutputStream;
import repack.org.bouncycastle.asn1.DERSequence;
import repack.org.bouncycastle.crypto.CipherParameters;
import repack.org.bouncycastle.crypto.DSA;
import repack.org.bouncycastle.crypto.Digest;
import repack.org.bouncycastle.crypto.digests.RIPEMD160Digest;
import repack.org.bouncycastle.crypto.digests.SHA1Digest;
import repack.org.bouncycastle.crypto.digests.SHA224Digest;
import repack.org.bouncycastle.crypto.digests.SHA256Digest;
import repack.org.bouncycastle.crypto.digests.SHA384Digest;
import repack.org.bouncycastle.crypto.digests.SHA512Digest;
import repack.org.bouncycastle.crypto.params.ParametersWithRandom;
import repack.org.bouncycastle.crypto.signers.ECDSASigner;
import repack.org.bouncycastle.crypto.signers.ECNRSigner;
import repack.org.bouncycastle.jce.interfaces.ECKey;
import repack.org.bouncycastle.jce.interfaces.ECPublicKey;
import repack.org.bouncycastle.jce.provider.DSABase;
import repack.org.bouncycastle.jce.provider.DSAEncoder;
import repack.org.bouncycastle.jce.provider.JDKKeyFactory;

public class Signature
    extends DSABase
{
    Signature(String name, Digest digest, DSA signer, DSAEncoder encoder)
    {
        super(name, digest, signer, encoder);
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        CipherParameters param;

        if (publicKey instanceof ECPublicKey)
        {
            param = ECUtil.generatePublicKeyParameter(publicKey);
        }
        else
        {
            try
            {
                byte[] bytes = publicKey.getEncoded();

                publicKey = JDKKeyFactory.createPublicKeyFromDERStream(bytes);

                if (publicKey instanceof ECPublicKey)
                {
                    param = ECUtil.generatePublicKeyParameter(publicKey);
                }
                else
                {
                    throw new InvalidKeyException("can't recognise key type in ECDSA based signer");
                }
            }
            catch (Exception e)
            {
                throw new InvalidKeyException("can't recognise key type in ECDSA based signer");
            }
        }

        digest.reset();
        signer.init(false, param);
    }

    protected void doEngineInitSign(PrivateKey privateKey, SecureRandom random)
        throws InvalidKeyException
    {
        CipherParameters param;

        if (privateKey instanceof ECKey)
        {
            param = ECUtil.generatePrivateKeyParameter(privateKey);
        }
        else
        {
            throw new InvalidKeyException("can't recognise key type in ECDSA based signer");
        }

        digest.reset();

        if (random != null)
        {
            signer.init(true, new ParametersWithRandom(param, random));
        }
        else
        {
            signer.init(true, param);
        }
    }

    static public class ecDSA
        extends Signature
    {
        public ecDSA()
        {
            super("ECDSA", new SHA1Digest(), new ECDSASigner(), new StdDSAEncoder());
        }
    }

    static public class ecDSAnone
        extends Signature
    {
        public ecDSAnone()
        {
            super("NONEwithECDSA", new NullDigest(), new ECDSASigner(), new StdDSAEncoder());
        }
    }

    static public class ecDSA224
        extends Signature
    {
        public ecDSA224()
        {
            super("ECDSAwithSHA224", new SHA224Digest(), new ECDSASigner(), new StdDSAEncoder());
        }
    }

    static public class ecDSA256
        extends Signature
    {
        public ecDSA256()
        {
            super("ECDSAwithSHA256", new SHA256Digest(), new ECDSASigner(), new StdDSAEncoder());
        }
    }

    static public class ecDSA384
        extends Signature
    {
        public ecDSA384()
        {
            super("ECDSAwithSHA384", new SHA384Digest(), new ECDSASigner(), new StdDSAEncoder());
        }
    }

    static public class ecDSA512
        extends Signature
    {
        public ecDSA512()
        {
            super("ECDSAwithSHA512", new SHA512Digest(), new ECDSASigner(), new StdDSAEncoder());
        }
    }

    static public class ecDSARipeMD160
        extends Signature
    {
        public ecDSARipeMD160()
        {
            super("ECDSAwithRIPEMD160", new RIPEMD160Digest(), new ECDSASigner(), new StdDSAEncoder());
        }
    }

    static public class ecNR
        extends Signature
    {
        public ecNR()
        {
            super("ECNR", new SHA1Digest(), new ECNRSigner(), new StdDSAEncoder());
        }
    }

    static public class ecNR224
        extends Signature
    {
        public ecNR224()
        {
            super("ECNRwithSHA224", new SHA224Digest(), new ECNRSigner(), new StdDSAEncoder());
        }
    }

    static public class ecNR256
        extends Signature
    {
        public ecNR256()
        {
            super("ECNRwithSHA256", new SHA256Digest(), new ECNRSigner(), new StdDSAEncoder());
        }
    }

    static public class ecNR384
        extends Signature
    {
        public ecNR384()
        {
            super("ECNRwithSHA384", new SHA384Digest(), new ECNRSigner(), new StdDSAEncoder());
        }
    }

    static public class ecNR512
        extends Signature
    {
        public ecNR512()
        {
            super("ECNRwithSHA512", new SHA512Digest(), new ECNRSigner(), new StdDSAEncoder());
        }
    }

    static public class ecCVCDSA
        extends Signature
    {
        public ecCVCDSA()
        {
            super("CVC-ECDSA", new SHA1Digest(), new ECDSASigner(), new CVCDSAEncoder());
        }
    }

    static public class ecCVCDSA224
        extends Signature
    {
        public ecCVCDSA224()
        {
            super("CVC-ECDSAwithSHA224", new SHA224Digest(), new ECDSASigner(), new CVCDSAEncoder());
        }
    }

    static public class ecCVCDSA256
        extends Signature
    {
        public ecCVCDSA256()
        {
            super("CVC-ECDSAwithSHA256", new SHA256Digest(), new ECDSASigner(), new CVCDSAEncoder());
        }
    }

    private static class StdDSAEncoder
        implements DSAEncoder
    {
        public byte[] encode(
            BigInteger r,
            BigInteger s)
            throws IOException
        {
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            DEROutputStream dOut = new DEROutputStream(bOut);
            ASN1EncodableVector v = new ASN1EncodableVector();

            v.add(new DERInteger(r));
            v.add(new DERInteger(s));

            dOut.writeObject(new DERSequence(v));

            return bOut.toByteArray();
        }

        public BigInteger[] decode(
            byte[] encoding)
            throws IOException
        {
            ASN1InputStream aIn = new ASN1InputStream(encoding);
            ASN1Sequence s = (ASN1Sequence)aIn.readObject();

            BigInteger[] sig = new BigInteger[2];

            sig[0] = ((DERInteger)s.getObjectAt(0)).getValue();
            sig[1] = ((DERInteger)s.getObjectAt(1)).getValue();

            return sig;
        }
    }

    private static class CVCDSAEncoder
        implements DSAEncoder
    {
        public byte[] encode(
            BigInteger r,
            BigInteger s)
            throws IOException
        {
            byte[] first = makeUnsigned(r);
            byte[] second = makeUnsigned(s);
            byte[] res;

            if (first.length > second.length)
            {
                res = new byte[first.length * 2];
            }
            else
            {
                res = new byte[second.length * 2];
            }

            System.arraycopy(first, 0, res, res.length / 2 - first.length, first.length);
            System.arraycopy(second, 0, res, res.length - second.length, second.length);

            return res;
        }


        private byte[] makeUnsigned(BigInteger val)
        {
            byte[] res = val.toByteArray();

            if (res[0] == 0)
            {
                byte[] tmp = new byte[res.length - 1];

                System.arraycopy(res, 1, tmp, 0, tmp.length);

                return tmp;
            }

            return res;
        }

        public BigInteger[] decode(
            byte[] encoding)
            throws IOException
        {
            BigInteger[] sig = new BigInteger[2];

            byte[] first = new byte[encoding.length / 2];
            byte[] second = new byte[encoding.length / 2];

            System.arraycopy(encoding, 0, first, 0, first.length);
            System.arraycopy(encoding, first.length, second, 0, second.length);

            sig[0] = new BigInteger(1, first);
            sig[1] = new BigInteger(1, second);

            return sig;
        }
    }

    private static class NullDigest
        implements Digest
    {
        private ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        public String getAlgorithmName()
        {
            return "NULL";
        }

        public int getDigestSize()
        {
            return bOut.size();
        }

        public void update(byte in)
        {
            bOut.write(in);
        }

        public void update(byte[] in, int inOff, int len)
        {
            bOut.write(in, inOff, len);
        }

        public int doFinal(byte[] out, int outOff)
        {
            byte[] res = bOut.toByteArray();

            System.arraycopy(res, 0, out, outOff, res.length);

            return res.length;
        }

        public void reset()
        {
            bOut.reset();
        }
    }
}
