package repack.org.bouncycastle.operator.bc;

import java.io.OutputStream;
import java.security.SecureRandom;

import repack.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import repack.org.bouncycastle.crypto.CryptoException;
import repack.org.bouncycastle.crypto.Signer;
import repack.org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import repack.org.bouncycastle.crypto.params.ParametersWithRandom;
import repack.org.bouncycastle.operator.ContentSigner;
import repack.org.bouncycastle.operator.OperatorCreationException;
import repack.org.bouncycastle.operator.RuntimeOperatorException;

public abstract class BcContentSignerBuilder
{
    private SecureRandom random;
    private AlgorithmIdentifier sigAlgId;
    private AlgorithmIdentifier digAlgId;

    public BcContentSignerBuilder(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
    {
        this.sigAlgId = sigAlgId;
        this.digAlgId = digAlgId;
    }

    public BcContentSignerBuilder setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    public ContentSigner build(AsymmetricKeyParameter privateKey)
        throws OperatorCreationException
    {
        final Signer sig = createSigner(sigAlgId, digAlgId);

        if (random != null)
        {
            sig.init(true, new ParametersWithRandom(privateKey, random));
        }
        else
        {
            sig.init(true, privateKey);
        }

        return new ContentSigner()
        {
            private BcSignerOutputStream stream = new BcSignerOutputStream(sig);

            public AlgorithmIdentifier getAlgorithmIdentifier()
            {
                return sigAlgId;
            }

            public OutputStream getOutputStream()
            {
                return stream;
            }

            public byte[] getSignature()
            {
                try
                {
                    return stream.getSignature();
                }
                catch (CryptoException e)
                {
                    throw new RuntimeOperatorException("exception obtaining signature: " + e.getMessage(), e);
                }
            }
        };
    }

    protected abstract Signer createSigner(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier algorithmIdentifier)
        throws OperatorCreationException;
}
