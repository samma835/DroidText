package repack.org.bouncycastle.operator.bc;

import repack.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import repack.org.bouncycastle.crypto.Digest;
import repack.org.bouncycastle.crypto.Signer;
import repack.org.bouncycastle.crypto.signers.RSADigestSigner;
import repack.org.bouncycastle.operator.OperatorCreationException;

public class BcRSAContentSignerBuilder
    extends BcContentSignerBuilder
{
    public BcRSAContentSignerBuilder(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
    {
        super(sigAlgId, digAlgId);
    }

    protected Signer createSigner(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
        throws OperatorCreationException
    {
        Digest dig = BcUtil.createDigest(digAlgId);

        return new RSADigestSigner(dig);
    }
}
