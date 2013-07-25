package repack.org.bouncycastle.cms;

import repack.org.bouncycastle.asn1.ASN1Set;

interface AuthAttributesProvider
{
    ASN1Set getAuthAttributes();
}
