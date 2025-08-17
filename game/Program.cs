using Anticheat;
using game;
using Npgsql;

string executable = Environment.GetCommandLineArgs()[0];
if (args.Length < 1)
{
    Console.WriteLine($"Usage:\n  As server: {executable} server [port]\n  As client: {executable} client <serverAddress> <port>");
    return;
}

if (args[0].ToLower() == "server")
{
    int port = (args.Length >= 2) ? int.Parse(args[1]) : 9050;
    // Connect to database
    var defaultConnString = "Host=localhost;Username=postgres;Password=example;Database=game";
    var connString = Environment.GetEnvironmentVariable("DATABASE") ?? defaultConnString;
    await using var conn = new NpgsqlConnection(connString);
    await conn.OpenAsync();
    // Prepare VPN list
    VpnList vpnList = new("https://raw.githubusercontent.com/X4BNet/lists_vpn/refs/heads/main/output/datacenter/ipv4.txt", "vpns.txt");
    await vpnList.InitializeAsync();
    new Server(port, conn, vpnList).Run();
}
else if (args[0].ToLower() == "client")
{
    if (args.Length < 3)
    {
        Console.WriteLine($"Usage for client: {executable} client <serverAddress> <port> <userid?>");
        return;
    }
    string address = args[1];
    int port = int.Parse(args[2]);
    Client.Run(address, port, int.Parse(args.ElementAtOrDefault(3) ?? "1"));
}
else
{
    Console.WriteLine("Invalid mode specified. Use 'server' or 'client'.");
}
