package repack.org.bouncycastle.operator;

import repack.org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public interface KeyUnwrapper
{
    AlgorithmIdentifier getAlgorithmIdentifier();

    GenericKey generateUnwrappedKey(AlgorithmIdentifier encryptionKeyAlgorithm, byte[] encryptedKey)
        throws OperatorException;
}
