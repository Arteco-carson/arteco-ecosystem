-- This script updates the UserProfiles table to include a reference to a Tenant.
-- This allows for a many-to-one relationship where a tenant can have multiple users.

-- Add a nullable TenantId column to the UserProfiles table.
ALTER TABLE dbo.UserProfiles
ADD TenantId INT NULL;
GO

-- Add a foreign key constraint to link UserProfiles to the Tenants table.
ALTER TABLE dbo.UserProfiles
ADD CONSTRAINT FK_UserProfiles_Tenants
FOREIGN KEY (TenantId) REFERENCES dbo.Tenants(TenantId);
GO

PRINT 'UserProfiles table updated successfully with TenantId and foreign key constraint.';
