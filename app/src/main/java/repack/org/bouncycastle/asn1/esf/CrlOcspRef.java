package repack.org.bouncycastle.asn1.esf;

import java.util.Enumeration;

import repack.org.bouncycastle.asn1.ASN1Encodable;
import repack.org.bouncycastle.asn1.ASN1EncodableVector;
import repack.org.bouncycastle.asn1.ASN1Sequence;
import repack.org.bouncycastle.asn1.DERObject;
import repack.org.bouncycastle.asn1.DERSequence;
import repack.org.bouncycastle.asn1.DERTaggedObject;

/**
 * <pre>
 * CrlOcspRef ::= SEQUENCE {
 *     crlids [0] CRLListID OPTIONAL,
 *     ocspids [1] OcspListID OPTIONAL,
 *     otherRev [2] OtherRevRefs OPTIONAL
 * }
 * </pre>
 */
public class CrlOcspRef
    extends ASN1Encodable
{

    private CrlListID crlids;
    private OcspListID ocspids;
    private OtherRevRefs otherRev;

    public static CrlOcspRef getInstance(Object obj)
    {
        if (obj instanceof CrlOcspRef)
        {
            return (CrlOcspRef)obj;
        }
        else if (obj != null)
        {
            return new CrlOcspRef(ASN1Sequence.getInstance(obj));
        }

        throw new IllegalArgumentException("null value in getInstance");
    }

    private CrlOcspRef(ASN1Sequence seq)
    {
        Enumeration e = seq.getObjects();
        while (e.hasMoreElements())
        {
            DERTaggedObject o = (DERTaggedObject)e.nextElement();
            switch (o.getTagNo())
            {
                case 0:
                    this.crlids = CrlListID.getInstance(o.getObject());
                    break;
                case 1:
                    this.ocspids = OcspListID.getInstance(o.getObject());
                    break;
                case 2:
                    this.otherRev = OtherRevRefs.getInstance(o.getObject());
                    break;
                default:
                    throw new IllegalArgumentException("illegal tag");
            }
        }
    }

    public CrlOcspRef(CrlListID crlids, OcspListID ocspids,
                      OtherRevRefs otherRev)
    {
        this.crlids = crlids;
        this.ocspids = ocspids;
        this.otherRev = otherRev;
    }

    public CrlListID getCrlids()
    {
        return this.crlids;
    }

    public OcspListID getOcspids()
    {
        return this.ocspids;
    }

    public OtherRevRefs getOtherRev()
    {
        return this.otherRev;
    }

    public DERObject toASN1Object()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        if (null != this.crlids)
        {
            v.add(new DERTaggedObject(true, 0, this.crlids.toASN1Object()));
        }
        if (null != this.ocspids)
        {
            v.add(new DERTaggedObject(true, 1, this.ocspids.toASN1Object()));
        }
        if (null != this.otherRev)
        {
            v.add(new DERTaggedObject(true, 2, this.otherRev.toASN1Object()));
        }
        return new DERSequence(v);
    }
}
