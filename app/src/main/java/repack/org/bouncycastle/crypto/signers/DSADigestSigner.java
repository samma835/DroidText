package repack.org.bouncycastle.crypto.signers;

import java.io.IOException;
import java.math.BigInteger;

import repack.org.bouncycastle.asn1.ASN1EncodableVector;
import repack.org.bouncycastle.asn1.ASN1Object;
import repack.org.bouncycastle.asn1.ASN1Sequence;
import repack.org.bouncycastle.asn1.DERInteger;
import repack.org.bouncycastle.asn1.DERSequence;
import repack.org.bouncycastle.crypto.CipherParameters;
import repack.org.bouncycastle.crypto.DSA;
import repack.org.bouncycastle.crypto.Digest;
import repack.org.bouncycastle.crypto.Signer;
import repack.org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import repack.org.bouncycastle.crypto.params.ParametersWithRandom;

public class DSADigestSigner
    implements Signer
{
    private final Digest digest;
    private final DSA dsaSigner;
    private boolean forSigning;

    public DSADigestSigner(
        DSA    signer,
        Digest digest)
    {
        this.digest = digest;
        this.dsaSigner = signer;
    }

    public void init(
        boolean           forSigning,
        CipherParameters   parameters)
    {
        this.forSigning = forSigning;

        AsymmetricKeyParameter k;

        if (parameters instanceof ParametersWithRandom)
        {
            k = (AsymmetricKeyParameter)((ParametersWithRandom)parameters).getParameters();
        }
        else
        {
            k = (AsymmetricKeyParameter)parameters;
        }

        if (forSigning && !k.isPrivate())
        {
            throw new IllegalArgumentException("Signing Requires Private Key.");
        }

        if (!forSigning && k.isPrivate())
        {
            throw new IllegalArgumentException("Verification Requires Public Key.");
        }

        reset();

        dsaSigner.init(forSigning, parameters);
    }

    /**
     * update the internal digest with the byte b
     */
    public void update(
        byte input)
    {
        digest.update(input);
    }

    /**
     * update the internal digest with the byte array in
     */
    public void update(
        byte[]  input,
        int     inOff,
        int     length)
    {
        digest.update(input, inOff, length);
    }

    /**
     * Generate a signature for the message we've been loaded with using
     * the key we were initialised with.
     */
    public byte[] generateSignature()
    {
        if (!forSigning)
        {
            throw new IllegalStateException("DSADigestSigner not initialised for signature generation.");
        }

        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);

        BigInteger[] sig = dsaSigner.generateSignature(hash);

        return derEncode(sig[0], sig[1]);
    }

    public boolean verifySignature(
        byte[] signature)
    {
        if (forSigning)
        {
            throw new IllegalStateException("DSADigestSigner not initialised for verification");
        }

        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);

        try
        {
            BigInteger[] sig = derDecode(signature);
            return dsaSigner.verifySignature(hash, sig[0], sig[1]);
        }
        catch (IOException e)
        {
            return false;
        }
    }

    public void reset()
    {
        digest.reset();
    }

    private byte[] derEncode(
        BigInteger  r,
        BigInteger  s)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERInteger(r));
        v.add(new DERInteger(s));

        return new DERSequence(v).getDEREncoded();
    }

    private BigInteger[] derDecode(
        byte[] encoding)
        throws IOException
    {
        ASN1Sequence s = (ASN1Sequence)ASN1Object.fromByteArray(encoding);

        return new BigInteger[]
        {
            ((DERInteger)s.getObjectAt(0)).getValue(),
            ((DERInteger)s.getObjectAt(1)).getValue()
        };
    }
}
