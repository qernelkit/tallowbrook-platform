using System.Text.Json;
using Tallowbrook.Billing.Web.Customers;
using Tallowbrook.Billing.Web.Invoices;
using Tallowbrook.Billing.Web.Portal;

namespace Tallowbrook.Billing.Web.SeedData;

/// <summary>Loads the development accounts and a few invoices so the portal has something to show locally.</summary>
internal static class DevelopmentSeeder
{
    private sealed record SeedUser(string Email, string DisplayName, string CustomerId, string TenantId, List<string> Roles, string PasswordHash);

    public static void Seed(IServiceProvider services, IHostEnvironment environment)
    {
        if (!environment.IsDevelopment())
        {
            return;
        }

        string path = Path.Combine(AppContext.BaseDirectory, "SeedData", "portal-users.json");
        List<SeedUser> seeds = JsonSerializer.Deserialize<List<SeedUser>>(File.ReadAllText(path)) ?? [];
        IPortalUserStore users = services.GetRequiredService<IPortalUserStore>();
        foreach (SeedUser seed in seeds)
        {
            users.Save(new PortalUser
            {
                Id = Guid.NewGuid(),
                Email = seed.Email,
                DisplayName = seed.DisplayName,
                CustomerId = seed.CustomerId,
                TenantId = seed.TenantId,
                Roles = seed.Roles,
                PasswordHash = seed.PasswordHash,
            });
        }

        var customers = (CustomerStore)services.GetRequiredService<ICustomerStore>();
        customers.Add(new Customer
        {
            Id = "TB-000001",
            TenantId = "tb-eu",
            Name = "Harbourline Imports GmbH",
            BillingEmail = "ap@harbourline.example",
            Country = "DE",
        });

        IInvoiceStore invoices = services.GetRequiredService<IInvoiceStore>();
        var today = DateOnly.FromDateTime(DateTime.UtcNow);
        for (int n = 1; n <= 5; n++)
        {
            var invoice = new Invoice
            {
                Id = Guid.NewGuid(),
                Number = $"2026{n:D6}",
                TenantId = "tb-eu",
                CustomerId = "TB-000001",
                Currency = "EUR",
                IssuedOn = today.AddDays(-14 * n),
                DueOn = today.AddDays(30 - 14 * n),
                Status = InvoiceStatus.Issued,
                Lines = [new InvoiceLine($"Groupage Hamburg - Rotterdam, shipment {n}", 1, "pcs", 420m + 35m * n, 0.19m)],
            };
            if (n > 1)
            {
                invoice.RecordPayment(invoice.Total);
            }

            invoices.Save(invoice);
        }
    }
}
