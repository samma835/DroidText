package repack.org.bouncycastle.asn1.x500;

import repack.org.bouncycastle.asn1.ASN1Encodable;
import repack.org.bouncycastle.asn1.ASN1EncodableVector;
import repack.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import repack.org.bouncycastle.asn1.ASN1Set;
import repack.org.bouncycastle.asn1.DERObject;
import repack.org.bouncycastle.asn1.DERSequence;
import repack.org.bouncycastle.asn1.DERSet;

public class RDN
    extends ASN1Encodable
{
    private ASN1Set values;

    private RDN(ASN1Set values)
    {
        this.values = values;
    }

    public static RDN getInstance(Object obj)
    {
        if (obj instanceof RDN)
        {
            return (RDN)obj;
        }
        else if (obj != null)
        {
            return new RDN(ASN1Set.getInstance(obj));
        }

        return null;
    }

    /**
     * Create a single valued RDN.
     *
     * @param oid
     * @param value
     */
    public RDN(ASN1ObjectIdentifier oid, ASN1Encodable value)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(oid);
        v.add(value);

        this.values = new DERSet(new DERSequence(v));
    }

    public RDN(AttributeTypeAndValue attrTAndV)
    {
        this.values = new DERSet(attrTAndV);
    }

    /**
     * Create a multi-valued RDN.
     */
    public RDN(AttributeTypeAndValue[] aAndVs)
    {
        this.values = new DERSet(aAndVs);
    }

    public boolean isMultiValued()
    {
        return this.values.size() > 1;
    }

    public AttributeTypeAndValue getFirst()
    {
        if (this.values.size() == 0)
        {
            return null;
        }

        return AttributeTypeAndValue.getInstance(this.values.getObjectAt(0));
    }

    public AttributeTypeAndValue[] getTypesAndValues()
    {
        AttributeTypeAndValue[] tmp = new AttributeTypeAndValue[values.size()];

        for (int i = 0; i != tmp.length; i++)
        {
            tmp[i] = AttributeTypeAndValue.getInstance(values.getObjectAt(i));
        }

        return tmp;
    }

    /**
     * <pre>
     * RelativeDistinguishedName ::=
     *                     SET OF AttributeTypeAndValue

     * AttributeTypeAndValue ::= SEQUENCE {
     *        type     AttributeType,
     *        value    AttributeValue }
     * </pre>
     * @return
     */
    public DERObject toASN1Object()
    {
        return values;
    }
}
