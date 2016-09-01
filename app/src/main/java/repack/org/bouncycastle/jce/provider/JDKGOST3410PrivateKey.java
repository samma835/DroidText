package repack.org.bouncycastle.jce.provider;

import repack.org.bouncycastle.asn1.ASN1Sequence;
import repack.org.bouncycastle.asn1.DEREncodable;
import repack.org.bouncycastle.asn1.DERObjectIdentifier;
import repack.org.bouncycastle.asn1.DEROctetString;
import repack.org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import repack.org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import repack.org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import repack.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import repack.org.bouncycastle.crypto.params.GOST3410PrivateKeyParameters;
import repack.org.bouncycastle.jce.interfaces.GOST3410Params;
import repack.org.bouncycastle.jce.interfaces.GOST3410PrivateKey;
import repack.org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import repack.org.bouncycastle.jce.spec.GOST3410ParameterSpec;
import repack.org.bouncycastle.jce.spec.GOST3410PrivateKeySpec;
import repack.org.bouncycastle.jce.spec.GOST3410PublicKeyParameterSetSpec;

import java.math.BigInteger;
import java.util.Enumeration;

public class JDKGOST3410PrivateKey
    implements GOST3410PrivateKey, PKCS12BagAttributeCarrier
{
    BigInteger          x;
    GOST3410Params      gost3410Spec;

    private PKCS12BagAttributeCarrier attrCarrier = new PKCS12BagAttributeCarrierImpl();

    protected JDKGOST3410PrivateKey()
    {
    }

    JDKGOST3410PrivateKey(
        GOST3410PrivateKey    key)
    {
        this.x = key.getX();
        this.gost3410Spec = key.getParameters();
    }

    JDKGOST3410PrivateKey(
        GOST3410PrivateKeySpec    spec)
    {
        this.x = spec.getX();
        this.gost3410Spec = new GOST3410ParameterSpec(new GOST3410PublicKeyParameterSetSpec(spec.getP(), spec.getQ(), spec.getA()));
    }

    JDKGOST3410PrivateKey(
        PrivateKeyInfo  info)
    {
        GOST3410PublicKeyAlgParameters    params = new GOST3410PublicKeyAlgParameters((ASN1Sequence)info.getAlgorithmId().getParameters());
        DEROctetString      derX = (DEROctetString)info.getPrivateKey();
        byte[]              keyEnc = derX.getOctets();
        byte[]              keyBytes = new byte[keyEnc.length];
        
        for (int i = 0; i != keyEnc.length; i++)
        {
            keyBytes[i] = keyEnc[keyEnc.length - 1 - i]; // was little endian
        }
        
        this.x = new BigInteger(1, keyBytes);
        this.gost3410Spec = GOST3410ParameterSpec.fromPublicKeyAlg(params);
    }

    JDKGOST3410PrivateKey(
        GOST3410PrivateKeyParameters  params,
        GOST3410ParameterSpec         spec)
    {
        this.x = params.getX();
        this.gost3410Spec = spec;

        if (spec == null) 
        {
            throw new IllegalArgumentException("spec is null");
        }
    }

    public String getAlgorithm()
    {
        return "GOST3410";
    }

    /**
     * return the encoding format we produce in getEncoded().
     *
     * @return the string "PKCS#8"
     */
    public String getFormat()
    {
        return "PKCS#8";
    }

    /**
     * Return a PKCS8 representation of the key. The sequence returned
     * represents a full PrivateKeyInfo object.
     *
     * @return a PKCS8 representation of the key.
     */
    public byte[] getEncoded()
    {
        PrivateKeyInfo          info;
        byte[]                  keyEnc = this.getX().toByteArray();
        byte[]                  keyBytes;

        if (keyEnc[0] == 0)
        {
            keyBytes = new byte[keyEnc.length - 1];
        }
        else
        {
            keyBytes = new byte[keyEnc.length];
        }
        
        for (int i = 0; i != keyBytes.length; i++)
        {
            keyBytes[i] = keyEnc[keyEnc.length - 1 - i]; // must be little endian
        }
        
        if (gost3410Spec instanceof GOST3410ParameterSpec)
        {
            info = new PrivateKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_94, new GOST3410PublicKeyAlgParameters(new DERObjectIdentifier(gost3410Spec.getPublicKeyParamSetOID()), new DERObjectIdentifier(gost3410Spec.getDigestParamSetOID())).getDERObject()), new DEROctetString(keyBytes));
        }
        else
        {
            info = new PrivateKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_94), new DEROctetString(keyBytes));
        }
        
        return info.getDEREncoded();
    }

    public GOST3410Params getParameters()
    {
        return gost3410Spec;
    }

    public BigInteger getX()
    {
        return x;
    }

    public void setBagAttribute(
        DERObjectIdentifier oid,
        DEREncodable        attribute)
    {
        attrCarrier.setBagAttribute(oid, attribute);
    }

    public DEREncodable getBagAttribute(
        DERObjectIdentifier oid)
    {
        return attrCarrier.getBagAttribute(oid);
    }

    public Enumeration getBagAttributeKeys()
    {
        return attrCarrier.getBagAttributeKeys();
    }
}
