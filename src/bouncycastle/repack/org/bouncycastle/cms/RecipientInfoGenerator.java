package repack.org.bouncycastle.cms;

import repack.org.bouncycastle.asn1.cms.RecipientInfo;
import repack.org.bouncycastle.operator.GenericKey;

public interface RecipientInfoGenerator
{
    RecipientInfo generate(GenericKey contentEncryptionKey)
        throws CMSException;
}
