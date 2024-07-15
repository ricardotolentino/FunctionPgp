using System.Text;
using Azure;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Logging;

namespace FunctionPgp
{
    internal static class Utilities
    {
        internal const string AppSettingKeyVaultUri = "KeyVaultUri";
        internal const string AppSettingPublicKeySecretName = "KeyVaultSecretNamePublicKey";
        internal const string AppSettingPrivateKeySecretName = "KeyVaultSecretNamePrivateKey";
        internal const string AppSettingPrivateKeyPasswordSecretName = "KeyVaultSecretNamePrivateKeyPassword";

        internal static void PrintAppSettingsLogger(ILogger Logger)
        {
            var Value = Environment.GetEnvironmentVariable("BlobConnectionMi__blobServiceUri");
            Logger.LogInformation($"Blob storage account = '{Value}'");

            var KeyVaultUri = Environment.GetEnvironmentVariable(AppSettingKeyVaultUri);
            Logger.LogInformation($"Key Vault URI = '{KeyVaultUri}'");

            var KeyVaultSecretNamePublicKey = Environment.GetEnvironmentVariable(AppSettingPublicKeySecretName);
            Logger.LogInformation($"Key Vault secret name for public key = '{KeyVaultSecretNamePublicKey}'");

            var KeyVaultSecretNamePrivateKey = Environment.GetEnvironmentVariable(AppSettingPrivateKeySecretName);
            Logger.LogInformation($"Key Vault secret name for private key = '{KeyVaultSecretNamePrivateKey}'");

            var KeyVaultSecretNamePrivateKeyPassword = Environment.GetEnvironmentVariable(AppSettingPrivateKeyPasswordSecretName);
            Logger.LogInformation($"Key Vault secret name for private key password = '{KeyVaultSecretNamePrivateKeyPassword}'");
        }

        internal static string DecodeBase64Secret(string EncodedSecret)
        {
            var DecodedSecretBytes = Convert.FromBase64String(EncodedSecret);
            var DecodedSecretString = Encoding.UTF8.GetString(DecodedSecretBytes);

            return DecodedSecretString;
        }

        internal static async Task<string> GetKeyVaultSecret(ILogger Logger, string KeyVaultUri, string KeyVaultSecretName, bool DecodeBase64 = false)
        {
            // Configure the Key Vault client
            var AzCred = new DefaultAzureCredential(new DefaultAzureCredentialOptions
            {
                ExcludeEnvironmentCredential = true,
                ExcludeWorkloadIdentityCredential = true,
                ExcludeSharedTokenCacheCredential = true,
                ExcludeVisualStudioCodeCredential = true,
                ExcludeAzureCliCredential = true,
                ExcludeAzurePowerShellCredential = true,
                ExcludeAzureDeveloperCliCredential = true,
                ExcludeInteractiveBrowserCredential = true,
            });
            var KeyVaultClient = new SecretClient(new Uri(KeyVaultUri), AzCred);

            // Get the Key Vault secret
            string KeyVaultSecretValue = "";
            try
            {
                var KeyVaultSecretResponse = await KeyVaultClient.GetSecretAsync(KeyVaultSecretName);
                var KeyVaultSecret = KeyVaultSecretResponse.Value;
                KeyVaultSecretValue = KeyVaultSecret.Value;
            }
            catch (RequestFailedException ex)
            {
                Logger.LogInformation($"ERROR: Secret '{KeyVaultSecretName}' does not exist - '{ex.Message}'.");
                return "";
            }
            catch (Exception ex)
            {
                Logger.LogInformation($"Error message = '{ex.Message}'");
                return "";
            }

            if (String.IsNullOrEmpty(KeyVaultSecretValue))
            {
                Logger.LogInformation($"Value for secret '{KeyVaultSecretName}' is an empty string ...");
                return "";
            }

            // Decode base64 encoded secret
            if (DecodeBase64)
            {
                var DecodedKey = DecodeBase64Secret(KeyVaultSecretValue);
                Logger.LogInformation("Decoded key from base64 ...");
                return DecodedKey;
            }
            else
            {
                return KeyVaultSecretValue;
            }
        }
    }
}
