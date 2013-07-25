package repack.org.bouncycastle.cert.crmf;

import java.io.IOException;
import java.io.OutputStream;

import repack.org.bouncycastle.asn1.cmp.PBMParameter;
import repack.org.bouncycastle.asn1.crmf.PKMACValue;
import repack.org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import repack.org.bouncycastle.operator.MacCalculator;
import repack.org.bouncycastle.util.Arrays;

class PKMACValueVerifier
{
    private final PKMACBuilder builder;

    public PKMACValueVerifier(PKMACBuilder builder)
    {
        this.builder = builder;
    }

    public boolean isValid(PKMACValue value, char[] password, SubjectPublicKeyInfo keyInfo)
        throws CRMFException
    {
        builder.setParameters(PBMParameter.getInstance(value.getAlgId().getParameters()));
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

        return Arrays.areEqual(calculator.getMac(), value.getValue().getBytes());
    }
}