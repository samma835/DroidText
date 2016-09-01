package repack.org.bouncycastle.crypto.tls;

import java.security.SecureRandom;

public interface TlsClientContext
{
    SecureRandom getSecureRandom();

    SecurityParameters getSecurityParameters();

    Object getUserObject();

    void setUserObject(Object userObject);
}
