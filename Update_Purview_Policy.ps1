# 1. Create a Service Principal in Azure Active Directory (Azure AD) and copy TENANT_ID, CLIENT_ID
# 2. Create a Client Secret and copy CLIENT_SECRET
# 3. Add the Service Principal to the Collection Administrator and the Data Curator roles within the Microsoft Purview account 
# 4. Update the variables below
# 5. Run script

# VARIABLES
$accountName = "YOUR_PURVIEW_ACCOUNT_NAME"
$clientId = "YOUR_CLINET_ID"
$tenantId = "YOUR_TENANT_ID"
$clientSecret = "YOUR_CLIENT_SECRET"
$objectId = "AN_AZURE_AD_OBJECT_ID"

# Endpoint
$pv_endpoint = "https://${accountName}.purview.azure.com"

# [GET] Metadata Policy
function getMetadataPolicy([string]$access_token, [string]$collectionName) {
    $uri = "${pv_endpoint}/policystore/collections/${collectionName}/metadataPolicy?api-version=2021-07-01"
    $response = Invoke-WebRequest $uri -Headers @{Authorization="Bearer $access_token"} -ContentType application/json -Method GET
    Return $response.Content | ConvertFrom-Json
}

# Modify Metadata Policy
function addRoleAssignment([object]$policy, [string]$principalId, [string]$roleName) {
    Foreach ($attributeRule in $policy.properties.attributeRules) {
        if (($attributeRule.name).StartsWith("purviewmetadatarole_builtin_${roleName}:")) {
            Foreach ($conditionArray in $attributeRule.dnfCondition) {
                Foreach($condition in $conditionArray) {
                    if ($condition.attributeName -eq "principal.microsoft.id") {
                        $condition.attributeValueIncludedIn += $principalId
                    }
                 }
            }
        }
    }
}

# [PUT] Metadata Policy
function putMetadataPolicy([string]$access_token, [string]$metadataPolicyId, [object]$payload) {
    $uri = "${pv_endpoint}/policystore/metadataPolicies/${metadataPolicyId}?api-version=2021-07-01"
    $body = ($payload | ConvertTo-Json -Depth 10)
    $response = Invoke-WebRequest $uri -Headers @{Authorization="Bearer $access_token"} -ContentType application/json -Method PUT -Body $body
    Return $response.Content | ConvertFrom-Json

}


# 1. Get access token 
$response = Invoke-WebRequest "https://login.microsoftonline.com/${tenantId}/oauth2/token" -ContentType application/x-www-form-urlencoded -Method POST -Body "grant_type=client_credentials&client_id=${clientId}&client_secret=${clientSecret}&resource=https://purview.azure.net"
$content = $response.Content | ConvertFrom-Json
$access_token = $content.access_token

# 2. Get root collection policy
$rootCollectionPolicy = getMetadataPolicy $access_token $accountName

# 3. Update root collection policy (add Azure AD object ID to built-in Microsoft Purview role)
addRoleAssignment $rootCollectionPolicy $objectId "data-curator"
#addRoleAssignment $rootCollectionPolicy $objectId "data-source-administrator"
#addRoleAssignment $rootCollectionPolicy $adfPrincipalId "data-curator"

# 4. Publish updated policy
$updatedPolicy = putMetadataPolicy $access_token $rootCollectionPolicy.id $rootCollectionPolicy
