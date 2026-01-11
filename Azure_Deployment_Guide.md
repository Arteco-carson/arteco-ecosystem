# Azure Deployment Guide

This guide provides instructions for configuring and deploying the Fine Art Ecosystem applications to Azure.

## 1. FineArtApi (C# API)

The API is now configured to use `appsettings.Production.json` when running in a Production environment.

### Configuration

1.  **Azure SQL Database:**
    *   Create an Azure SQL Database instance.
    *   Update the `FineArtApi/appsettings.Production.json` file with your Azure SQL Database connection string. Replace the placeholder values.

    ```json
    {
      "ConnectionStrings": {
        "DefaultConnection": "Server=tcp:<your-azure-sql-server-name>.database.windows.net,1433;Initial Catalog=<your-database-name>;Persist Security Info=False;User ID=<your-username>;Password=<your-password>;MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"
      }
    }
    ```

2.  **Deployment:**
    *   You can deploy the API to an Azure App Service.
    *   When you publish the project, make sure to set the `ASPNETCORE_ENVIRONMENT` to `Production`. This can be done in the Azure App Service configuration settings.

## 2. arteco-acm-frontend (React Web App)

This application was already configured to use environment variables.

### Configuration

1.  **API Endpoint:**
    *   When building the application for production, set the `REACT_APP_API_URL` environment variable to the URL of your deployed `FineArtApi`.

    Example for a build script in `package.json`:
    ```json
    "build:production": "REACT_APP_API_URL=https://<your-api-app-name>.azurewebsites.net/api npm run build"
    ```

## 3. arteco-dr-frontend (React Vite Web App)

The application has been updated to use environment variables for the API endpoint.

### Configuration

1.  **API Endpoint:**
    *   The API endpoint is configured in `.env.production` and `.env.development` files.
    *   Update `arteco-dr-frontend/.env.production` with the URL of your deployed `FineArtApi`.

    ```
    VITE_API_URL=https://<your-azure-app-service-name>.azurewebsites.net/api
    ```

## 4. arteco-acm-mobile & arteco-dr-mobile (React Native Mobile Apps)

Both mobile applications have been updated to use environment variables for the API endpoint. This requires the `react-native-dotenv` package.

### Setup

1.  **Install `react-native-dotenv`:**
    *   For both `arteco-acm-mobile` and `arteco-dr-mobile` directories, run:
        ```bash
        npm install react-native-dotenv
        ```
        or
        ```bash
        yarn add react-native-dotenv
        ```

2.  **Update `babel.config.js`:**
    *   In both mobile app directories, add the `module:react-native-dotenv` plugin to your `babel.config.js` file.

    ```javascript
    module.exports = {
      presets: ['module:metro-react-native-babel-preset'],
      plugins: [
        ['module:react-native-dotenv', {
          'moduleName': '@env',
          'path': '.env',
          'blacklist': null,
          'whitelist': null,
          'safe': false,
          'allowUndefined': true
        }]
      ]
    };
    ```
    *Note: If you have an existing `babel.config.js`, merge the plugins array.*

### Configuration

1.  **API Endpoint:**
    *   For each mobile app, there is an `.env.production` file. Update this file with the URL of your deployed `FineArtApi`.

    **`arteco-acm-mobile/.env.production`:**
    ```
    API_URL=https://<your-azure-app-service-name>.azurewebsites.net/api
    IS_PRODUCTION=true
    ```

    **`arteco-dr-mobile/.env.production`:**
    ```
    API_URL=https://<your-azure-app-service-name>.azurewebsites.net/api
    ```

2.  **Building for Production:**
    *   When you build your mobile app for production, the `.env.production` file will be used by `react-native-dotenv` to provide the correct API endpoint. Consult the documentation for your build process and `react-native-dotenv` for more details on environment-specific builds.
