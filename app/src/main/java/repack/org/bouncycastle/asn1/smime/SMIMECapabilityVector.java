package repack.org.bouncycastle.asn1.smime;

import repack.org.bouncycastle.asn1.ASN1EncodableVector;
import repack.org.bouncycastle.asn1.DEREncodable;
import repack.org.bouncycastle.asn1.DERInteger;
import repack.org.bouncycastle.asn1.DERObjectIdentifier;
import repack.org.bouncycastle.asn1.DERSequence;

/**
 * Handler for creating a vector S/MIME Capabilities
 */
public class SMIMECapabilityVector
{
    private ASN1EncodableVector    capabilities = new ASN1EncodableVector();

    public void addCapability(
        DERObjectIdentifier capability)
    {
        capabilities.add(new DERSequence(capability));
    }

    public void addCapability(
        DERObjectIdentifier capability,
        int                 value)
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add(capability);
        v.add(new DERInteger(value));

        capabilities.add(new DERSequence(v));
    }

    public void addCapability(
        DERObjectIdentifier capability,
        DEREncodable        params)
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add(capability);
        v.add(params);

        capabilities.add(new DERSequence(v));
    }

    public ASN1EncodableVector toASN1EncodableVector()
    {
        return capabilities;
    }
}
