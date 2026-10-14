namespace Tallowbrook.Billing.Web.Invoices.Pricing;

public enum DeliveryMode
{
    Bike,
    Van,
    Truck,
    Rail,
    Sea,
    Air,
}

public sealed record Shipment(DeliveryMode Mode, int Zone, decimal WeightKg, decimal VolumeM3, bool Express);

public sealed record FreightQuote(decimal Net, string Basis);

/// <summary>
/// List prices per delivery mode and zone. Contract customers get their discount on the invoice line,
/// not here, so the quote shown in the portal always matches the published rate card.
/// </summary>
public sealed class FreightRateCalculator
{
    // Road and rail are billed on the greater of actual and volumetric weight.
    private const decimal VolumetricKgPerM3 = 333m;
    private const decimal AirVolumetricKgPerM3 = 167m;
    private const decimal ExpressSurcharge = 0.35m;

    private static readonly decimal[] ZoneFactors = [1.00m, 1.15m, 1.35m, 1.60m, 2.10m];

    public FreightQuote Quote(Shipment shipment)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(shipment.WeightKg);
        if (shipment.Zone < 1 || shipment.Zone > ZoneFactors.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(shipment), shipment.Zone, "Unknown delivery zone.");
        }

        decimal zoneFactor = ZoneFactors[shipment.Zone - 1];
        decimal net;
        string basis;

        switch (shipment.Mode)
        {
            case DeliveryMode.Bike:
                // City courier: flat per drop up to 25 kg, then the van rate applies.
                if (shipment.WeightKg > 25m)
                {
                    return Quote(shipment with { Mode = DeliveryMode.Van });
                }

                net = 9.50m * zoneFactor;
                basis = "flat courier rate";
                break;
            case DeliveryMode.Van:
                net = (24m + 0.42m * Chargeable(shipment, VolumetricKgPerM3)) * zoneFactor;
                basis = "van, per chargeable kg";
                break;
            case DeliveryMode.Truck:
                net = (85m + 0.18m * Chargeable(shipment, VolumetricKgPerM3)) * zoneFactor;
                basis = "groupage, per chargeable kg";
                break;
            case DeliveryMode.Rail:
                net = (140m + 0.11m * Chargeable(shipment, VolumetricKgPerM3)) * zoneFactor;
                basis = "rail, per chargeable kg";
                break;
            case DeliveryMode.Sea:
                net = 210m + 48m * Math.Max(1m, shipment.VolumeM3) * zoneFactor;
                basis = "sea, per m3 (minimum 1 m3)";
                break;
            case DeliveryMode.Air:
                net = (60m + 2.85m * Chargeable(shipment, AirVolumetricKgPerM3)) * zoneFactor;
                basis = "air, per chargeable kg";
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(shipment), shipment.Mode, "Unknown delivery mode.");
        }

        if (shipment.Express && shipment.Mode is not DeliveryMode.Sea)
        {
            net *= 1m + ExpressSurcharge;
            basis += ", express";
        }

        return new FreightQuote(decimal.Round(net, 2, MidpointRounding.AwayFromZero), basis);
    }

    private static decimal Chargeable(Shipment shipment, decimal kgPerM3) =>
        Math.Max(shipment.WeightKg, shipment.VolumeM3 * kgPerM3);
}
