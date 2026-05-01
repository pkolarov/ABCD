using DDS.PolicyAgent.Linux.Client;

namespace DDS.PolicyAgent.Linux.Tests;

public sealed class DdsNodeHttpFactoryTests
{
    [Fact]
    public void ResolvesUnixSocketToPlaceholderHttpBase()
    {
        Assert.Equal(new Uri("http://localhost/"),
            DdsNodeHttpFactory.ResolveBaseAddress("unix:/run/dds/api.sock"));
    }

    [Fact]
    public void ExtractsUnixSocketPath()
    {
        Assert.Equal("/run/dds/api.sock",
            DdsNodeHttpFactory.ExtractSocketPath("unix:/run/dds/api.sock"));
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
