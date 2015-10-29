package repack.org.bouncycastle.cms;

import java.util.Date;
import java.util.Hashtable;
import java.util.Map;

import repack.org.bouncycastle.asn1.DERObjectIdentifier;
import repack.org.bouncycastle.asn1.DEROctetString;
import repack.org.bouncycastle.asn1.DERSet;
import repack.org.bouncycastle.asn1.cms.Attribute;
import repack.org.bouncycastle.asn1.cms.AttributeTable;
import repack.org.bouncycastle.asn1.cms.CMSAttributes;
import repack.org.bouncycastle.asn1.cms.Time;

/**
 * Default signed attributes generator.
 */
public class DefaultSignedAttributeTableGenerator
    implements CMSAttributeTableGenerator
{
    private final Hashtable table;

    /**
     * Initialise to use all defaults
     */
    public DefaultSignedAttributeTableGenerator()
    {
        table = new Hashtable();
    }

    /**
     * Initialise with some extra attributes or overrides.
     *
     * @param attributeTable initial attribute table to use.
     */
    public DefaultSignedAttributeTableGenerator(
        AttributeTable attributeTable)
    {
        if (attributeTable != null)
        {
            table = attributeTable.toHashtable();
        }
        else
        {
            table = new Hashtable();
        }
    }

    /**
     * Create a standard attribute table from the passed in parameters - this will
     * normally include contentType, signingTime, and messageDigest. If the constructor
     * using an AttributeTable was used, entries in it for contentType, signingTime, and
     * messageDigest will override the generated ones.
     *
     * @param parameters source parameters for table generation.
     *
     * @return a filled in Hashtable of attributes.
     */
    protected Hashtable createStandardAttributeTable(
        Map parameters)
    {
        Hashtable std = (Hashtable)table.clone();

        if (!std.containsKey(CMSAttributes.contentType))
        {
            DERObjectIdentifier contentType = (DERObjectIdentifier)
                parameters.get(CMSAttributeTableGenerator.CONTENT_TYPE);

            // contentType will be null if we're trying to generate a counter signature.
            if (contentType != null)
            {
                Attribute attr = new Attribute(CMSAttributes.contentType,
                    new DERSet(contentType));
                std.put(attr.getAttrType(), attr);
            }
        }

        if (!std.containsKey(CMSAttributes.signingTime))
        {
            Date signingTime = new Date();
            Attribute attr = new Attribute(CMSAttributes.signingTime,
                new DERSet(new Time(signingTime)));
            std.put(attr.getAttrType(), attr);
        }

        if (!std.containsKey(CMSAttributes.messageDigest))
        {
            byte[] messageDigest = (byte[])parameters.get(
                CMSAttributeTableGenerator.DIGEST);
            Attribute attr = new Attribute(CMSAttributes.messageDigest,
                new DERSet(new DEROctetString(messageDigest)));
            std.put(attr.getAttrType(), attr);
        }

        return std;
    }

    /**
     * @param parameters source parameters
     * @return the populated attribute table
     */
    public AttributeTable getAttributes(Map parameters)
    {
        return new AttributeTable(createStandardAttributeTable(parameters));
    }
}
