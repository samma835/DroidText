package repack.org.bouncycastle.cms.jcajce;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import repack.org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import repack.org.bouncycastle.cms.CMSAttributeTableGenerator;
import repack.org.bouncycastle.cms.SignerInfoGenerator;
import repack.org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import repack.org.bouncycastle.operator.ContentSigner;
import repack.org.bouncycastle.operator.DigestCalculatorProvider;
import repack.org.bouncycastle.operator.OperatorCreationException;

public class JcaSignerInfoGeneratorBuilder
    extends SignerInfoGeneratorBuilder
{
    public JcaSignerInfoGeneratorBuilder(DigestCalculatorProvider digestProvider)
    {
        super(digestProvider);
    }

    /**
     * If the passed in flag is true, the signer signature will be based on the data, not
     * a collection of signed attributes, and no signed attributes will be included.
     *
     * @return the builder object
     */
    public SignerInfoGeneratorBuilder setDirectSignature(boolean hasNoSignedAttributes)
    {
        super.setDirectSignature(hasNoSignedAttributes);

        return this;
    }

    public SignerInfoGeneratorBuilder setSignedAttributeGenerator(CMSAttributeTableGenerator signedGen)
    {
        super.setSignedAttributeGenerator(signedGen);

        return this;
    }

    public SignerInfoGeneratorBuilder setUnsignedAttributeGenerator(CMSAttributeTableGenerator unsignedGen)
    {
        super.setUnsignedAttributeGenerator(unsignedGen);

        return this;
    }

    public SignerInfoGenerator build(ContentSigner contentSigner, X509Certificate certificate)
        throws OperatorCreationException, CertificateEncodingException
    {
        return super.build(contentSigner, new JcaX509CertificateHolder(certificate));
    }
}
