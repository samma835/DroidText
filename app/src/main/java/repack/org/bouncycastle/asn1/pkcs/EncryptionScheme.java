package repack.org.bouncycastle.asn1.pkcs;

import repack.org.bouncycastle.asn1.ASN1EncodableVector;
import repack.org.bouncycastle.asn1.ASN1Sequence;
import repack.org.bouncycastle.asn1.DEREncodable;
import repack.org.bouncycastle.asn1.DERObject;
import repack.org.bouncycastle.asn1.DERObjectIdentifier;
import repack.org.bouncycastle.asn1.DERSequence;
import repack.org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class EncryptionScheme
    extends AlgorithmIdentifier
{
    public EncryptionScheme(
        DERObjectIdentifier objectId,
        DEREncodable parameters)
    {
        super(objectId, parameters);
    }

    EncryptionScheme(
        ASN1Sequence  seq)
    {   
        this((DERObjectIdentifier)seq.getObjectAt(0), seq.getObjectAt(1));
    }

    public static final AlgorithmIdentifier getInstance(Object obj)
    {
        if (obj instanceof EncryptionScheme)
        {
            return (EncryptionScheme)obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new EncryptionScheme((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public DERObject getObject()
    {
        return (DERObject)getParameters();
    }

    public DERObject getDERObject()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add(getObjectId());
        v.add(getParameters());

        return new DERSequence(v);
    }
}
