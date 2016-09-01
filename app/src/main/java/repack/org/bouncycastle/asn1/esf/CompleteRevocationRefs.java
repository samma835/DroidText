package repack.org.bouncycastle.asn1.esf;

import java.util.Enumeration;

import repack.org.bouncycastle.asn1.ASN1Encodable;
import repack.org.bouncycastle.asn1.ASN1Sequence;
import repack.org.bouncycastle.asn1.DERObject;
import repack.org.bouncycastle.asn1.DERSequence;

/**
 * <pre>
 * CompleteRevocationRefs ::= SEQUENCE OF CrlOcspRef
 * </pre>
 */
public class CompleteRevocationRefs
    extends ASN1Encodable
{

    private ASN1Sequence crlOcspRefs;

    public static CompleteRevocationRefs getInstance(Object obj)
    {
        if (obj instanceof CompleteRevocationRefs)
        {
            return (CompleteRevocationRefs)obj;
        }
        else if (obj != null)
        {
            return new CompleteRevocationRefs(ASN1Sequence.getInstance(obj));
        }

        throw new IllegalArgumentException("null value in getInstance");
    }

    private CompleteRevocationRefs(ASN1Sequence seq)
    {
        Enumeration seqEnum = seq.getObjects();
        while (seqEnum.hasMoreElements())
        {
            CrlOcspRef.getInstance(seqEnum.nextElement());
        }
        this.crlOcspRefs = seq;
    }

    public CompleteRevocationRefs(CrlOcspRef[] crlOcspRefs)
    {
        this.crlOcspRefs = new DERSequence(crlOcspRefs);
    }

    public CrlOcspRef[] getCrlOcspRefs()
    {
        CrlOcspRef[] result = new CrlOcspRef[this.crlOcspRefs.size()];
        for (int idx = 0; idx < result.length; idx++)
        {
            result[idx] = CrlOcspRef.getInstance(this.crlOcspRefs
                .getObjectAt(idx));
        }
        return result;
    }

    public DERObject toASN1Object()
    {
        return this.crlOcspRefs;
    }
}
