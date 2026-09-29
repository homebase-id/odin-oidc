using System.Net;
using System.Net.Sockets;

namespace Odin.Oidc.Login.Registration;

/// <summary>
/// Where a client document may be fetched from. The URL in a client id is chosen by whoever sends
/// the authorize request, so the fetch must never reach this host's own network: nothing in the
/// IANA special-use registries (RFC 6890): loopback, private, link-local, carrier NAT, multicast,
/// documentation, unspecified. The check is on the resolved addresses, at connect time, so a name
/// that resolves to a private address, or rebinds to one, is refused too.
/// </summary>
public static class SafeAddress
{
    public static bool IsPublic(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = address.GetAddressBytes();
            return !(b[0] == 0                                  // 0.0.0.0/8 "this network"
                     || b[0] == 10                              // 10/8
                     || b[0] == 127                             // loopback
                     || (b[0] == 100 && (b[1] & 0xC0) == 64)    // 100.64/10 carrier NAT
                     || (b[0] == 169 && b[1] == 254)            // link-local
                     || (b[0] == 172 && (b[1] & 0xF0) == 16)    // 172.16/12
                     || (b[0] == 192 && b[1] == 0 && b[2] is 0 or 2) // 192.0.0/24, 192.0.2/24 TEST-NET-1
                     || (b[0] == 192 && b[1] == 88 && b[2] == 99) // 6to4 relay
                     || (b[0] == 192 && b[1] == 168)            // 192.168/16
                     || (b[0] == 198 && (b[1] & 0xFE) == 18)    // 198.18/15 benchmarking
                     || (b[0] == 198 && b[1] == 51 && b[2] == 100) // TEST-NET-2
                     || (b[0] == 203 && b[1] == 0 && b[2] == 113)  // TEST-NET-3
                     || b[0] >= 224);                           // multicast, reserved, broadcast
        }
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var b = address.GetAddressBytes();
            return !(address.Equals(IPAddress.IPv6Any) || address.Equals(IPAddress.IPv6Loopback)
                     || address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6UniqueLocal
                     || address.IsIPv6Multicast || address.IsIPv6Teredo
                     || (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8) // 2001:db8::/32 documentation
                     || (b[0] == 0 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b)); // 64:ff9b::/96 NAT64: an IPv4 in disguise
        }
        return false;
    }

    /// <summary>
    /// A SocketsHttpHandler connect callback that resolves the name itself and connects only to
    /// public addresses. <paramref name="allowLocal"/> is for a development broker whose relying
    /// parties run on this machine (the draft's one exception, loopback for a development AS).
    /// </summary>
    public static Func<SocketsHttpConnectionContext, CancellationToken, ValueTask<Stream>> Connect(bool allowLocal) => async (context, ct) =>
    {
        var host = context.DnsEndPoint.Host;
        var resolved = IPAddress.TryParse(host, out var literal) ? [literal] : await Dns.GetHostAddressesAsync(host, ct);
        var usable = allowLocal ? resolved : resolved.Where(IsPublic).ToArray();
        if (usable.Length == 0)
        {
            throw new HttpRequestException($"{host} resolves to no public address");
        }

        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(usable, context.DnsEndPoint.Port, ct);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    };
}
