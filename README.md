# AzureADPermissionExplorer

Bash script that checks permission granted to service principals and the SPs owners

## Requirements
Azure CLI

## TODO
Add flags and parameters to choose file output names.

~~Add a list of high permissions and flag permissions that are on that list in the output and in the console~~

Optimize API calls by caching Graph-API permissions. This would probebly speed up the script significantly.

Add column for if the application has any secrets that are still in use

Add column for if an app is a managed identity
