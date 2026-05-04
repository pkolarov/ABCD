using DDS.PolicyAgent.Linux.Client;

namespace DDS.PolicyAgent.Linux.Tests;

public sealed class DdsNodeHttpFactoryTests
{
    [Fact]
    public void ResolvesUnixSocketToPlaceholderHttpBase()
    {
        Assert.Equal(new Uri("http://localhost/"),
            DdsNodeHttpFactory.ResolveBaseAddress("unix:/var/lib/dds/dds.sock"));
    }

    [Fact]
    public void ExtractsUnixSocketPath()
    {
        Assert.Equal("/var/lib/dds/dds.sock",
            DdsNodeHttpFactory.ExtractSocketPath("unix:/var/lib/dds/dds.sock"));
    }

    [Fact]
    public void RejectsEmptyUnixSocketPath()
    {
        Assert.Throws<ArgumentException>(() => DdsNodeHttpFactory.ExtractSocketPath("unix:"));
    }

    [Fact]
    public void PreservesTcpBaseAddress()
    {
        Assert.Equal(new Uri("http://127.0.0.1:5551/"),
            DdsNodeHttpFactory.ResolveBaseAddress("http://127.0.0.1:5551"));
    }
}
