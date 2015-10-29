package repack.org.bouncycastle.cert.crmf.jcajce;

import java.security.Provider;
import java.security.PublicKey;

import javax.security.auth.x500.X500Principal;

import repack.org.bouncycastle.asn1.crmf.CertReqMsg;
import repack.org.bouncycastle.asn1.x500.X500Name;
import repack.org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import repack.org.bouncycastle.cert.crmf.CRMFException;
import repack.org.bouncycastle.cert.crmf.CertificateRequestMessage;
import repack.org.bouncycastle.jcajce.DefaultJcaJceHelper;
import repack.org.bouncycastle.jcajce.NamedJcaJceHelper;
import repack.org.bouncycastle.jcajce.ProviderJcaJceHelper;

public class JcaCertificateRequestMessage
    extends CertificateRequestMessage
{
    private CRMFHelper helper = new CRMFHelper(new DefaultJcaJceHelper());

    public JcaCertificateRequestMessage(CertificateRequestMessage certReqMsg)
    {
        this(certReqMsg.toASN1Structure());
    }

    public JcaCertificateRequestMessage(CertReqMsg certReqMsg)
    {
        super(certReqMsg);
    }

    public JcaCertificateRequestMessage setProvider(String providerName)
    {
        this.helper = new CRMFHelper(new NamedJcaJceHelper(providerName));

        return this;
    }

    public JcaCertificateRequestMessage setProvider(Provider provider)
    {
        this.helper = new CRMFHelper(new ProviderJcaJceHelper(provider));

        return this;
    }

    public X500Principal getSubjectX500Principal()
    {
        X500Name subject = this.getCertTemplate().getSubject();

        if (subject != null)
        {
            return new X500Principal(subject.getDEREncoded());
        }

        return null;
    }

    public PublicKey getPublicKey()
        throws CRMFException
    {
        SubjectPublicKeyInfo subjectPublicKeyInfo = getCertTemplate().getPublicKey();

        if (subjectPublicKeyInfo != null)
        {
            return helper.toPublicKey(subjectPublicKeyInfo);
        }

        return null;
    }
}
