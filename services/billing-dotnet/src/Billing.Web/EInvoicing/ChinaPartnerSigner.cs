using Microsoft.Extensions.Options;
using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Tallowbrook.Billing.Web.EInvoicing;

/// <summary>
/// The Shenzhen forwarder's invoice API only accepts invoice XML signed with the key we registered with
/// them at onboarding. The key is provisioned as a secret; nothing here generates one.
/// </summary>
public sealed class ChinaPartnerSigner
{
    private static readonly X9ECParameters Sm2Curve = GMNamedCurves.GetByName("sm2p256v1");

    private readonly ECPrivateKeyParameters _key;

    public ChinaPartnerSigner(IOptions<EInvoicingOptions> options)
    {
        var domain = new ECDomainParameters(Sm2Curve);
        _key = new ECPrivateKeyParameters(new BigInteger(options.Value.ChinaPartnerKeyHex, 16), domain);
    }

    public string Sign(byte[] invoiceXml)
    {
        var signer = new SM2Signer();
        signer.Init(true, new ParametersWithRandom(_key, new SecureRandom()));
        signer.BlockUpdate(invoiceXml, 0, invoiceXml.Length);
        return Convert.ToBase64String(signer.GenerateSignature());
    }
}
