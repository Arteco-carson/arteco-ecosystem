# Troubleshooting Guide

## Issue: 500 Error on Collection Creation

**Symptoms:**

- When creating a new collection, the frontend displays an error message: "Failed to create collection: AxiosError" and "Failed to load resource: the server responded with a status of 500 ()".
- Despite the error, the collection is successfully created in the database.

**Root Cause:**

The 500 error was caused by an issue in the `FineArtApi/Controllers/CollectionsController.cs` file. The `PostCollection` method was using an incorrect `CreatedAtAction` configuration.

Specifically, the `CreatedAtAction` was pointing to the `GetCollections` (plural) method, but it should have been pointing to the `GetCollection` (singular) method, which is the standard pattern for returning a newly created resource.

Additionally, the `PostCollection` method was returning the entire `Collection` object, which contained circular references due to navigation properties. This would have caused a JSON serialization error.

**Fix:**

1. **Corrected `CreatedAtAction`:**
   - The `CreatedAtAction` in `PostCollection` was changed to point to `nameof(GetCollection)`.

2. **Improved Returned Object:**
   - Instead of returning the entire `Collection` object, a new anonymous object is created and returned. This object contains only the necessary information (`CollectionId`, `CollectionName`, `Description`, `ArtworkCount`) and avoids serialization errors.

3. **Updated Frontend URLs:**
   - All hardcoded instances of `https://localhost:7056` in the `arteco-frontend` directory were replaced with `http://localhost:5000` to match the backend's launch settings. This ensures that the frontend application is communicating with the correct backend endpoint.
