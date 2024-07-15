using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using PgpCore;

namespace FunctionPgp
{
    public static class FunctionPgp
    {
        [Function("FunctionEncode")]
        [BlobOutput("gpg-destination/encrypted_{name}.gpg", Connection = "StorageAccountUriEncode")]
        public static async Task<string> Encode(
            [BlobTrigger("gpg-source/source_{name}.csv", Connection = "StorageAccountUriEncode")] string BlobTriggerContent,
            FunctionContext Context)
        {
            var Logger = Context.GetLogger("BlobFunction");
            Utilities.PrintAppSettingsLogger(Logger);
            var KeyVaultUri = Environment.GetEnvironmentVariable(Utilities.AppSettingKeyVaultUri) ?? "";
            var KeyVaultSecretNamePublicKey = Environment.GetEnvironmentVariable(Utilities.AppSettingPublicKeySecretName) ?? "";

            // Get and decode base64 public key secret
            var PublicKey = await Utilities.GetKeyVaultSecret(Logger, KeyVaultUri, KeyVaultSecretNamePublicKey, true);
            if (String.IsNullOrEmpty(PublicKey))
            {
                // TODO: Is this the best way to handle this error?
                throw new Exception("ERROR: Failed to get and decode public key from Key Vault ...");
            }

            // Load public key
            EncryptionKeys EncryptionKeys = new EncryptionKeys(PublicKey);
            PGP Pgp = new PGP(EncryptionKeys);
            Logger.LogInformation("Loaded public key ...");

            // Encrypt blob using public key
            var EncryptedContent = await Pgp.EncryptAsync(BlobTriggerContent);
            Logger.LogInformation("Encrypted blob ...");

            // Write to blob output
            return $"{EncryptedContent}";
        }

        [Function("FunctionDecode")]
        [BlobOutput("gpg-destination/decrypted_{name}.txt", Connection = "StorageAccountUriDecode")]
        public static async Task<string> Decode(
            [BlobTrigger("gpg-source/encrypted_{name}.gpg", Connection = "StorageAccountUriDecode")] string BlobTriggerContent,
            FunctionContext Context)
        {
            var Logger = Context.GetLogger("BlobFunction");
            Utilities.PrintAppSettingsLogger(Logger);
            var KeyVaultUri = Environment.GetEnvironmentVariable(Utilities.AppSettingKeyVaultUri) ?? "";
            var KeyVaultSecretNamePrivateKey = Environment.GetEnvironmentVariable(Utilities.AppSettingPrivateKeySecretName) ?? "";
            var KeyVaultSecretNamePrivateKeyPassword = Environment.GetEnvironmentVariable(Utilities.AppSettingPrivateKeyPasswordSecretName) ?? "";

            // Get and decode base64 private key secret
            var PrivateKey = await Utilities.GetKeyVaultSecret(Logger, KeyVaultUri, KeyVaultSecretNamePrivateKey, true);
            if (String.IsNullOrEmpty(PrivateKey))
            {
                // TODO: Is this the best way to handle this error?
                throw new Exception("ERROR: Failed to get and decode private key from Key Vault ...");
            }

            // Get private key password secret
            var PrivateKeyPassword = await Utilities.GetKeyVaultSecret(Logger, KeyVaultUri, KeyVaultSecretNamePrivateKeyPassword, false);
            if (String.IsNullOrEmpty(PrivateKeyPassword))
            {
                Logger.LogInformation("Empty secret value for private key password");
                // TODO: Is this the best way to handle this error?
                throw new Exception("ERROR: Failed to get private key password from Key Vault ...");
            }

            // Load private key
            EncryptionKeys EncryptionKeys = new EncryptionKeys(PrivateKey, PrivateKeyPassword);
            PGP Pgp = new PGP(EncryptionKeys);
            Logger.LogInformation("Loaded private key ...");

            // Decrypt blob using private key
            var DecryptedContent = await Pgp.DecryptAsync(BlobTriggerContent);
            Logger.LogInformation("Decrypted blob ...");

            // Write to blob output
            return $"{DecryptedContent}";
        }
    }
}
