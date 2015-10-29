package repack.org.bouncycastle.cert.crmf;

import java.io.IOException;
import java.io.OutputStream;

import repack.org.bouncycastle.asn1.DERBitString;
import repack.org.bouncycastle.asn1.crmf.PKMACValue;
import repack.org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import repack.org.bouncycastle.operator.MacCalculator;

class PKMACValueGenerator
{
    private PKMACBuilder builder;

    public PKMACValueGenerator(PKMACBuilder builder)
    {
        this.builder = builder;
    }

    public PKMACValue generate(char[] password, SubjectPublicKeyInfo keyInfo)
        throws CRMFException
    {
        MacCalculator calculator = builder.build(password);

        OutputStream macOut = calculator.getOutputStream();

        try
        {
            macOut.write(keyInfo.getDEREncoded());

            macOut.close();
        }
        catch (IOException e)
        {
            throw new CRMFException("exception encoding mac input: " + e.getMessage(), e);
        }

        return new PKMACValue(calculator.getAlgorithmIdentifier(), new DERBitString(calculator.getMac()));
    }
}
