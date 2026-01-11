# FineArtApi Configuration

This application is configured to use environment variables for sensitive settings. This is a security best practice and is required for deployment to Azure.

## Environment Variables

The following environment variables must be set in your Azure App Service configuration or your local development environment:

-   `ConnectionStrings__DefaultConnection`: The connection string for the Azure SQL database.
-   `Jwt__Key`: A strong, secret key for signing JWT tokens.
-   `AzureStorage__ConnectionString`: The connection string for the Azure Storage account.

### Local Development

For local development, you can use a `appsettings.Development.json` file to store these secrets, but **do not commit this file to source control**.

Example `appsettings.Development.json`:

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=.\\SQLEXPRESS;Initial Catalog=Arteco-Collection-Mgr;Persist Security Info=False;User ID=AppUser;Password=Art3c0-Syst3m;MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=True;Connection Timeout=30;"
  },
  "Jwt": {
    "Key": "A_much_stronger_secret_key_that_is_not_the_default_one"
  },
  "AzureStorage": {
    "ConnectionString": "your_azure_storage_connection_string"
  }
}
```

Make sure your local development environment is configured to use the "Development" environment. This is typically done by setting the `ASPNETCORE_ENVIRONMENT` environment variable to `Development`.
