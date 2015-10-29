package repack.org.bouncycastle.asn1.cmp;

import repack.org.bouncycastle.asn1.ASN1Choice;
import repack.org.bouncycastle.asn1.ASN1Encodable;
import repack.org.bouncycastle.asn1.ASN1TaggedObject;
import repack.org.bouncycastle.asn1.DERObject;
import repack.org.bouncycastle.asn1.DERTaggedObject;
import repack.org.bouncycastle.asn1.crmf.EncryptedValue;

public class CertOrEncCert
    extends ASN1Encodable
    implements ASN1Choice
{
    private CMPCertificate certificate;
    private EncryptedValue encryptedCert;

    private CertOrEncCert(ASN1TaggedObject tagged)
    {
        if (tagged.getTagNo() == 0)
        {
            certificate = CMPCertificate.getInstance(tagged.getObject());
        }
        else if (tagged.getTagNo() == 1)
        {
            encryptedCert = EncryptedValue.getInstance(tagged.getObject());
        }
        else
        {
            throw new IllegalArgumentException("unknown tag: " + tagged.getTagNo());
        }
    }

    public static CertOrEncCert getInstance(Object o)
    {
        if (o instanceof CertOrEncCert)
        {
            return (CertOrEncCert)o;
        }

        if (o instanceof ASN1TaggedObject)
        {
            return new CertOrEncCert((ASN1TaggedObject)o);
        }

        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public CertOrEncCert(CMPCertificate certificate)
    {
        if (certificate == null)
        {
            throw new IllegalArgumentException("'certificate' cannot be null");
        }

        this.certificate = certificate;
    }

    public CertOrEncCert(EncryptedValue encryptedCert)
    {
        if (encryptedCert == null)
        {
            throw new IllegalArgumentException("'encryptedCert' cannot be null");
        }

        this.encryptedCert = encryptedCert;
    }

    public CMPCertificate getCertificate()
    {
        return certificate;
    }

    public EncryptedValue getEncryptedCert()
    {
        return encryptedCert;
    }

    /**
     * <pre>
     * CertOrEncCert ::= CHOICE {
     *                      certificate     [0] CMPCertificate,
     *                      encryptedCert   [1] EncryptedValue
     *           }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public DERObject toASN1Object()
    {
        if (certificate != null)
        {
            return new DERTaggedObject(true, 0, certificate);
        }

        return new DERTaggedObject(true, 1, encryptedCert);
    }
}
