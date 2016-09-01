package repack.org.bouncycastle.cms;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.zip.DeflaterOutputStream;

import repack.org.bouncycastle.asn1.ASN1OctetString;
import repack.org.bouncycastle.asn1.BERConstructedOctetString;
import repack.org.bouncycastle.asn1.DERObjectIdentifier;
import repack.org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import repack.org.bouncycastle.asn1.cms.CompressedData;
import repack.org.bouncycastle.asn1.cms.ContentInfo;
import repack.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import repack.org.bouncycastle.operator.OutputCompressor;

/**
 * General class for generating a compressed CMS message.
 * <p>
 * A simple example of usage.
 * <p>
 * <pre>
 *      CMSCompressedDataGenerator  fact = new CMSCompressedDataGenerator();
 *
 *      CMSCompressedData           data = fact.generate(content, new ZlibCompressor());
 * </pre>
 */
public class CMSCompressedDataGenerator
{
    public static final String  ZLIB    = "1.2.840.113549.1.9.16.3.8";

    /**
     * base constructor
     */
    public CMSCompressedDataGenerator()
    {
    }

    /**
     * generate an object that contains an CMS Compressed Data
     * @deprecated use generate(CMSTypedData, OutputCompressor)
     */
    public CMSCompressedData generate(
        CMSProcessable  content,
        String          compressionOID)
        throws CMSException
    {
        AlgorithmIdentifier     comAlgId;
        ASN1OctetString         comOcts;

        try
        {
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            DeflaterOutputStream  zOut = new DeflaterOutputStream(bOut);

            content.write(zOut);

            zOut.close();

            comAlgId = new AlgorithmIdentifier(new DERObjectIdentifier(compressionOID));
            comOcts = new BERConstructedOctetString(bOut.toByteArray());
        }
        catch (IOException e)
        {
            throw new CMSException("exception encoding data.", e);
        }

        ContentInfo     comContent = new ContentInfo(
                                    CMSObjectIdentifiers.data, comOcts);

        ContentInfo     contentInfo = new ContentInfo(
                                    CMSObjectIdentifiers.compressedData,
                                    new CompressedData(comAlgId, comContent));

        return new CMSCompressedData(contentInfo);
    }

    /**
     * generate an object that contains an CMS Compressed Data
     */
    public CMSCompressedData generate(
        CMSTypedData content,
        OutputCompressor compressor)
        throws CMSException
    {
        AlgorithmIdentifier     comAlgId;
        ASN1OctetString         comOcts;

        try
        {
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            OutputStream zOut = compressor.getOutputStream(bOut);

            content.write(zOut);

            zOut.close();

            comAlgId = compressor.getAlgorithmIdentifier();
            comOcts = new BERConstructedOctetString(bOut.toByteArray());
        }
        catch (IOException e)
        {
            throw new CMSException("exception encoding data.", e);
        }

        ContentInfo     comContent = new ContentInfo(
                                    content.getContentType(), comOcts);

        ContentInfo     contentInfo = new ContentInfo(
                                    CMSObjectIdentifiers.compressedData,
                                    new CompressedData(comAlgId, comContent));

        return new CMSCompressedData(contentInfo);
    }
}
