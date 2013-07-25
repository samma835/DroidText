package repack.org.bouncycastle.cms.bc;

import repack.org.bouncycastle.cert.X509CertificateHolder;
import repack.org.bouncycastle.cms.KeyTransRecipientInfoGenerator;
import repack.org.bouncycastle.operator.bc.BcAsymmetricKeyWrapper;

public abstract class BcKeyTransRecipientInfoGenerator
    extends KeyTransRecipientInfoGenerator
{
    public BcKeyTransRecipientInfoGenerator(X509CertificateHolder recipientCert, BcAsymmetricKeyWrapper wrapper)
    {
        super(recipientCert.getIssuerAndSerialNumber(), wrapper);
    }

    public BcKeyTransRecipientInfoGenerator(byte[] subjectKeyIdentifier, BcAsymmetricKeyWrapper wrapper)
    {
        super(subjectKeyIdentifier, wrapper);
    }
}