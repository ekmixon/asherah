using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using GoDaddy.Asherah.SecureMemory.ProtectedMemoryImpl;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace GoDaddy.Asherah.SecureMemory.Tests.ProtectedMemoryImpl
{
    [Collection("Logger Fixture collection")]
    public class ProtectedMemorySecretFactoryTest
    {
        private readonly IConfiguration configuration;

        public ProtectedMemorySecretFactoryTest()
        {
            Trace.Listeners.Clear();
            var consoleListener = new ConsoleTraceListener();
            Trace.Listeners.Add(consoleListener);

            var configDictionary = new Dictionary<string, string>();
            configDictionary["debugSecrets"] = "true";

            configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(configDictionary)
                .Build();
        }

        // TODO Mocking static methods is not yet possible in Moq framework.
        // If it gets possible then we can add test these flows
        [Fact]
        private void TestProtectedMemorySecretFactoryWithMac()
        {
        }

        [Fact]
        private void TestProtectedMemorySecretFactoryWithLinux()
        {
        }

        [Fact]
        private void TestProtectedMemorySecretFactoryWithWindowsShouldFail()
        {
        }

        [SkippableFact]
        private void TestOpenSSLConfigurationLinux()
        {
            Skip.IfNot(RuntimeInformation.IsOSPlatform(OSPlatform.Linux));

            var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string>()
            {
                {"secureHeapEngine", "openssl11"}
            }).Build();

            Debug.WriteLine("ProtectedMemorySecretFactoryTest.TestOpenSSLConfigurationLinux");
            using (var factory = new ProtectedMemorySecretFactory(configuration))
            {
            }
        }

        [SkippableFact]
        private void TestOpenSSLConfigurationMacOS()
        {
            Skip.IfNot(RuntimeInformation.IsOSPlatform(OSPlatform.OSX));

            var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string>()
            {
                {"secureHeapEngine", "openssl11"}
            }).Build();

            Debug.WriteLine("ProtectedMemorySecretFactoryTest.TestOpenSSLConfiguration");
            Assert.Throws<PlatformNotSupportedException>(() =>
            {
                using (var factory = new ProtectedMemorySecretFactory(configuration))
                {
                }
            });
        }

        [Fact]
        private void TestMmapConfiguration()
        {
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string>()
            {
                {"secureHeapEngine", "mmap"}
            }).Build();

            Debug.WriteLine("ProtectedMemorySecretFactoryTest.TestMmapConfiguration");
            using (var factory = new ProtectedMemorySecretFactory(configuration))
            {
            }
        }

        [Fact]
        private void TestInvalidConfiguration()
        {
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string>()
            {
                {"secureHeapEngine", "magic-heap-engine2"}
            }).Build();

            Debug.WriteLine("ProtectedMemorySecretFactoryTest.TestMmapConfiguration");
            Assert.Throws<PlatformNotSupportedException>(() =>
            {
                using (var factory = new ProtectedMemorySecretFactory(configuration))
                {
                }
            });
        }

        [Fact]
        private void TestCreateSecretByteArray()
        {
            Debug.WriteLine("ProtectedMemorySecretFactoryTest.TestCreateSecretByteArray");
            using (var factory = new ProtectedMemorySecretFactory(configuration))
            {
                using Secret secret = factory.CreateSecret(new byte[] { 0, 1 });
                Assert.Equal(typeof(ProtectedMemorySecret), secret.GetType());
            }
        }

        [Fact]
        private void TestCreateSecretCharArray()
        {
            Debug.WriteLine("ProtectedMemorySecretFactoryTest.TestCreateSecretCharArray");
            using (var factory = new ProtectedMemorySecretFactory(configuration))
            {
                using Secret secret = factory.CreateSecret(new[] { 'a', 'b' });
                Assert.Equal(typeof(ProtectedMemorySecret), secret.GetType());
            }
        }

        [Fact]
        private void TestDoubleDispose()
        {
            var factory = new ProtectedMemorySecretFactory(configuration);
            factory.Dispose();
            Assert.Throws<Exception>(() => {
                factory.Dispose();
             });
        }
    }
}
