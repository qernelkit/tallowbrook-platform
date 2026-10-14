using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using Microsoft.Extensions.Options;

namespace Tallowbrook.Billing.Web.EInvoicing;

/// <summary>
/// Public-sector buyers require the e-invoice XML to carry an enveloped XML signature by our
/// e-invoicing certificate (issued from the CSR that enroll-einvoice-cert writes).
/// </summary>
public sealed class PublicSectorInvoiceSigner(IOptions<EInvoicingOptions> options)
{
    private readonly Lazy<X509Certificate2> _certificate = new(() =>
        X509CertificateLoader.LoadPkcs12FromFile(options.Value.SigningCertificatePath, options.Value.SigningCertificatePassword));

    public XmlDocument Sign(XmlDocument invoice)
    {
        X509Certificate2 certificate = _certificate.Value;
        using RSA key = certificate.GetRSAPrivateKey() ?? throw new InvalidOperationException("The e-invoicing PFX holds no RSA key.");

        var signedXml = new SignedXml(invoice) { SigningKey = key };
        signedXml.SignedInfo!.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
        signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;

        var reference = new Reference(string.Empty) { DigestMethod = SignedXml.XmlDsigSHA256Url };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        signedXml.AddReference(reference);

        var keyInfo = new KeyInfo();
        keyInfo.AddClause(new KeyInfoX509Data(certificate));
        signedXml.KeyInfo = keyInfo;

        signedXml.ComputeSignature();
        XmlElement signature = signedXml.GetXml();
        invoice.DocumentElement!.AppendChild(invoice.ImportNode(signature, deep: true));
        return invoice;
    }
}
