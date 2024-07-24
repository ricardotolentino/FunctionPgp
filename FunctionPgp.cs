using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using PgpCore;

namespace FunctionPgp
{
    public static class FunctionPgp
    {
        [Function("FunctionEncode")]
        public static async Task Encode(
            [BlobTrigger("gpg-source/source_{TriggerBlobName}.csv", Connection = "StorageAccountEncodeUriTrigger")] Stream BlobTriggerContent,
            string TriggerBlobName,
            FunctionContext Context)
        {
            var Logger = Context.GetLogger("BlobFunction");

            // Print and get App Settings
            Utilities.PrintAppSettingsLogger(Logger, "encode");
            var KeyVaultUri = Environment.GetEnvironmentVariable(Utilities.AppSettingKeyVaultUri) ?? "";
            var KeyVaultSecretNamePublicKey = Environment.GetEnvironmentVariable(Utilities.AppSettingPublicKeySecretName) ?? "";
            var StorageAccountUriEncodeDestination = Environment.GetEnvironmentVariable(Utilities.AppSettingStorageAccountEncodeUriDestination) ?? "";
            var StorageAccountContainerEncodeDestination = Environment.GetEnvironmentVariable(Utilities.AppSettingStorageAccountEncodeContainerDestination) ?? "";

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

            // Get a stream to the destination blob for the encrypted content
            var DestinationBlobName = $"{StorageAccountUriEncodeDestination}/{StorageAccountContainerEncodeDestination}/encrypted_{TriggerBlobName}.gpg";
            var EncryptedDestinationBlobStream = Utilities.GetBlobWriteStream(DestinationBlobName);
            Logger.LogInformation($"Opened write stream to blob destination '{DestinationBlobName}' ...");

            // Encrypt blob using public key
            await Pgp.EncryptAsync(BlobTriggerContent, EncryptedDestinationBlobStream);
            Logger.LogInformation("Encrypted blob ...");
        }

        [Function("FunctionDecode")]
        public static async Task Decode(
            [BlobTrigger("gpg-source/encrypted_{TriggerBlobName}.gpg", Connection = "StorageAccountDecodeUriTrigger")] Stream BlobTriggerContent,
            string TriggerBlobName,
            FunctionContext Context)
        {
            var Logger = Context.GetLogger("BlobFunction");

            // Print and get App Settings
            Utilities.PrintAppSettingsLogger(Logger, "decode");
            var KeyVaultUri = Environment.GetEnvironmentVariable(Utilities.AppSettingKeyVaultUri) ?? "";
            var KeyVaultSecretNamePrivateKey = Environment.GetEnvironmentVariable(Utilities.AppSettingPrivateKeySecretName) ?? "";
            var KeyVaultSecretNamePrivateKeyPassword = Environment.GetEnvironmentVariable(Utilities.AppSettingPrivateKeyPasswordSecretName) ?? "";
            var StorageAccountUriDecodeDestination = Environment.GetEnvironmentVariable(Utilities.AppSettingStorageAccountDecodeUriDestination) ?? "";
            var StorageAccountContainerDecodeDestination = Environment.GetEnvironmentVariable(Utilities.AppSettingStorageAccountDecodeContainerDestination) ?? "";

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

            // Get a stream to the destination blob for the decrypted content
            var DestinationBlobName = $"{StorageAccountUriDecodeDestination}/{StorageAccountContainerDecodeDestination}/decrypted_{TriggerBlobName}.csv";
            var DecryptedDestinationBlobStream = Utilities.GetBlobWriteStream(DestinationBlobName);
            Logger.LogInformation($"Opened write stream to blob destination '{DestinationBlobName}' ...");

            // Decrypt blob using private key
            // !!! This is the official stream decryption method per PgpCore, but this produces an empty file
            //await Pgp.DecryptAsync(BlobTriggerContent, DecryptedDestinationBlobStream);
            //
            // Alternatively, read and write the stream manually
            using (var StreamReader = new StreamReader(BlobTriggerContent))
            using (var StreamWriter = new StreamWriter(DecryptedDestinationBlobStream))
            {
                // Read the content from the triggered blob
                var Content = await StreamReader.ReadToEndAsync();

                // Decrypt the blob content
                var DecryptedContent = await Pgp.DecryptAsync(Content);

                // Write the decrypted content to the destination blob
                await StreamWriter.WriteAsync(DecryptedContent);
            }


            Logger.LogInformation("Decrypted blob ...");
        }
    }
}
