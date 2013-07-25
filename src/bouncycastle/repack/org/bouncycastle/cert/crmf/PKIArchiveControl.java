package repack.org.bouncycastle.cert.crmf;

import repack.org.bouncycastle.asn1.ASN1Encodable;
import repack.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import repack.org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import repack.org.bouncycastle.asn1.cms.ContentInfo;
import repack.org.bouncycastle.asn1.cms.EnvelopedData;
import repack.org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers;
import repack.org.bouncycastle.asn1.crmf.EncryptedKey;
import repack.org.bouncycastle.asn1.crmf.PKIArchiveOptions;
import repack.org.bouncycastle.cms.CMSEnvelopedData;

/**
 * Carrier for a PKIArchiveOptions structure.
 */
public class PKIArchiveControl
    implements Control
{
    public static final int encryptedPrivKey = PKIArchiveOptions.encryptedPrivKey;
    public static final int keyGenParameters = PKIArchiveOptions.keyGenParameters;
    public static final int archiveRemGenPrivKey = PKIArchiveOptions.archiveRemGenPrivKey;

    private static final ASN1ObjectIdentifier type = CRMFObjectIdentifiers.id_regCtrl_pkiArchiveOptions;

    private final PKIArchiveOptions pkiArchiveOptions;

    /**
     * Basic constructor - build from an PKIArchiveOptions structure.
     *
     * @param pkiArchiveOptions  the ASN.1 structure that will underlie this control.
     */
    public PKIArchiveControl(PKIArchiveOptions pkiArchiveOptions)
    {
        this.pkiArchiveOptions = pkiArchiveOptions;
    }

    /**
     * Return the type of this control.
     *
     * @return CRMFObjectIdentifiers.id_regCtrl_pkiArchiveOptions
     */
    public ASN1ObjectIdentifier getType()
    {
        return type;
    }

    /**
     * Return the underlying ASN.1 object.
     *
     * @return a PKIArchiveOptions structure.
     */
    public ASN1Encodable getValue()
    {
        return pkiArchiveOptions;
    }

    /**
     * Return the archive control type, one of: encryptedPrivKey,keyGenParameters,or archiveRemGenPrivKey.
     *
     * @return the archive control type.
     */
    public int getArchiveType()
    {
        return pkiArchiveOptions.getType();
    }

    /**
     * Return whether this control contains enveloped data.
     *
     * @return true if the control contains enveloped data, false otherwise.
     */
    public boolean isEnvelopedData()
    {
        EncryptedKey encKey = EncryptedKey.getInstance(pkiArchiveOptions.getValue());

        return !encKey.isEncryptedValue();
    }

    /**
     * Return the enveloped data structure contained in this control.
     *
     * @return a CMSEnvelopedData object.
     */
    public CMSEnvelopedData getEnvelopedData()
    {
        EncryptedKey encKey = EncryptedKey.getInstance(pkiArchiveOptions.getValue());
        EnvelopedData data = EnvelopedData.getInstance(encKey.getValue());
        
        return new CMSEnvelopedData(new ContentInfo(CMSObjectIdentifiers.envelopedData, data));
    }
}
