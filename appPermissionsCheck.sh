#!/bin/bash

function printRow(){

    printToStdOut=$1
    outputFileName=$2
    appendToFile=$3
    echoArr=("${@:4}")

    row=$(printf "$delimiter%s" "${echoArr[@]}")
    row=${row:1}

    if [ "$printToStdOut" == true ]
    then
        echo $row
    fi

    if [ $appendToFile == true ]; then
        echo $row >> $outputFileName
    elif [ $appendToFile == false ]; then
        echo $row > $outputFileName
    elif [ $appendToFile == "dontPrint" ]; then
        return 1
    fi

    return 1
}

declare -A ownerPermissionsAppId
declare -A ownerPermissionsAppName

function addToOwnerDict(){

    value=$1
    appId=$2
    appName=$3
    base=$(echo "$value" | base64 -w 0)

    if [ ${ownerPermissionsAppId[$base]+_} ]
    then
        exsistingAppId=${ownerPermissionsAppId[$base]}

        if [[ "$exsistingAppId" == *"$appId"* ]]; then
            return 0
        fi

        ownerPermissionsAppId[$base]="$exsistingAppId $appId"

        exsistingAppName=${ownerPermissionsAppName[$base]}
        ownerPermissionsAppName[$base]="$exsistingAppName $appName"
    else
         ownerPermissionsAppId+=([$base]=$appId)
         ownerPermissionsAppName+=([$base]=$appName)
    fi
}

function getOwnerAppIds(){
    value=$1
    base=$(echo "$value" | base64 -w 0)

    if [ ${ownerPermissionsAppId[$base]+_} ]
    then
        ${ownerPermissionsAppId[$base]}
        return 0
    else
        return 1
    fi
}

function getOwnerAppNames(){
    value=$1
    base=$(echo "$value" | base64 -w 0)

    if [ ${ownerPermissionsAppName[$base]+_} ]
    then
        echo ${ownerPermissionsAppName[$base]}
        return 0
    else
        echo "do not exist"
        return 1
    fi
}

function getOwners(){

    returnArr=()

    for i in "${!ownerPermissionsAppId[@]}"
    do
        deBase=$(echo -n "$i" | base64 -d)
        appIds=$(getOwnerAppIds "$i")
        appNames=$(getOwnerAppNames "$i")
        returnArr+="$deBase;$appIds;$appNames\n"
    done

    echo -e $returnArr
}

declare -A dangerousApiPermissions=(
    ["1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9"]="Allows the application to act as other entities, and use any priviliges they have" # Application.ReadWrite.All
    ["06b708a9-e830-4db3-a914-8e69da51d44f"]="Allows the application to grant any API permissions to itself or another application" # AppRoleAssignment.ReadWrite.All
    ["9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"]="Allows the application to grant priviliges to itself or other applications/users" # RoleManagement.ReadWrite.Directory
    ["19dbc75e-c2e2-444c-a770-ec69d8559fc7"]="Allows the application to read and write data in AAD, including group memberships" # Directory.ReadWrite.All
    ["741f803b-c850-494e-b5df-cde7c675a1ca"]="Allows the application to read all data for a user, including resetting passowrds but not for priviliged admin account (same permissions as helpdesk administrator)" # User.ReadWrite.All
    ["62a82d76-70ea-41e2-9197-370581804d09"]="Allows the application to read and write groups, including modifying group memberships" # Group.ReadWrite.All
    ["9492366f-7969-46a4-8d15-ed1a20078fff"]="Allows the application to read and write documents in all sharepoint/onedirve sites" # Sites.ReadWrite.All
    ["a82116e5-55eb-4c41-a434-62fe8a61c773"]="Allows the application full control of all sharepoint sites" # Sites.FullControl.All
    ["75359482-378d-4052-8f01-80520e7db3cd"]="Allows the application to read or write data to all files in sharepoint/onedrive" # Files.ReadWrite.All
    ["810c84a8-4a9e-49e6-bf7d-12d183f40d01"]="Allows the application to read mail in any mail box. This permission can be limited to specific mailboxes with \"application access policies\"" # Mail.Read
    ["e2a3a72e-5f79-4c64-b1b1-878b674786c9"]="Allows the application to read or write mail in any mail box (not send). This permission can be limited to specific mailboxes with \"application access policies\"" # Mail.ReadWrite
    ["b633e1c5-b582-4048-a93e-9f11b44c7e96"]="Allows the application to send emails from any mail box. This permission can be limited to specific mailboxes with \"application access policies\"" # Mail.Send
)


function getDangerousApiPermissions() {
    applicationPermissionId=$1

    if [ ${dangerousApiPermissions[$applicationPermissionId]+_} ]
    then
        returnVal=${dangerousApiPermissions[$applicationPermissionId]}
        echo "true" "$returnVal"
    else
        echo "false"
    fi
}

# check requirements
azReq=$(command -v az)
if [ $? -ne 0 ]
then
    echo 'Error: "az" command not found.This script require the Azure CLI to be installed'
    exit 2
fi

login=$(az account show)
if [ $? -ne 0 ]
then
    echo "Error: Azure CLI is not logged in. Please run az login before running this script"
    exit 3
fi

delimiter=";"

outputFilenameApps="apps_output.csv"
outputFilenameOwners="owners_output.csv"

appHeader=("appId" "appDisplayName" "permissionResource" "permissionName" "permissionDescription" "permissionType" "permissionId" "appOwners" "isDangerous" "comment" "LatestPasswordExpiryDate", "LatestKeyExpiryDate")
printRow true $outputFilenameApps false "${appHeader[@]}"

ownerHeader=("userPrincipalName" "permissionResource" "permissionName" "permissionDescription" "permissionType" "permissionId" "appId" "appDisplayName" "isDangerous" "comment")
printRow false $outputFilenameOwners false "${ownerHeader[@]}"

if [ -n "$1" ]
then
	appList=$1
else
	appList=$(az ad app list --all --query "[*].appId" --output tsv)
    appFullList=$(az ad app list --all)
fi

for id in $appList
do

    appDisplayName=$(az ad app show --id $id --query "displayName" | sed 's/\"//g')
    appPermissions=$(az ad app permission list --id $id --query "[*]" | jq -r '.[] | .resourceAppId + ";" + .resourceAccess[].id + ";" + .resourceAccess[].type')
    appOwners=$(az ad app owner list --id $id --query "[*].userPrincipalName" | jq -r '. | join(" ")')
    
    appPassSecrets=$(echo -e $appFullList | jq --arg id "$id" '.[] | select(.appId=="$id"), .passwordCredentials[].endDateTime, .keyCredentials[].endDateTime' | sort -r | head -n 1)
    appKeySecrets=$(echo -e $appFullList | jq --arg id "$id" '.[] | select(.appId=="$id"), .keyCredentials[].endDateTime' | sort -r | head -n 1)

    for permissions in $appPermissions
    do
        resourceId=$(echo $permissions | awk -F ";" '{ print $1 }')
        permissionId=$(echo $permissions | awk -F ";" '{ print $2 }')
        permissionType=$(echo $permissions | awk -F ";" '{ print $3 }' | sed 's/Role/Application/' | sed 's/Scope/Delegated/')

        permissionsRequest=$(az rest --url "https://graph.microsoft.com/v1.0/servicePrincipals?\$filter=appId eq '$resourceId'&\$select=appId, displayName, appRoles, oauth2PermissionScopes")
        permissionsResourceDisplayName=$(echo $permissionsRequest | jq --arg id $resourceId -r '.value[]  |  select (.appId==$id) | .displayName')
        permissionName=$(echo $permissionsRequest | jq --arg permId $permissionId -r '.value[] | .appRoles[], .oauth2PermissionScopes[] | select (.id==$permId) | .value')
        permissionDesc=$(echo $permissionsRequest | jq --arg permId $permissionId -r '.value[] | .appRoles[], .oauth2PermissionScopes[] | select (.id==$permId)  | .description +""+ .adminConsentDescription')

        dangerousPermissions=$(getDangerousApiPermissions $permissionId)
        permissionIsDangerous=$(echo $dangerousPermissions | cut -d' ' -f1)
        dangerousDescription=$(echo $dangerousPermissions | cut -d' ' -f2- -s)

        echoArr=("$id" "$appDisplayName" "$permissionsResourceDisplayName" "$permissionName" "$permissionDesc" "$permissionType" "$permissionId" "$appOwners" "$permissionIsDangerous" "$dangerousDescription" "$appPassSecrets" "$appKeySecrets")
        printRow true $outputFilenameApps true "${echoArr[@]}"

        for owner in $appOwners
        do
            echoArr=("$owner" "$permissionsResourceDisplayName" "$permissionName" "$permissionDesc" "$permissionType" "$permissionId")
            ownerString=$(printRow true $outputFilenameOwners "dontPrint" "${echoArr[@]}")
            addToOwnerDict "$ownerString" "$id" "$appDisplayName"
        done

    done
done

for key in "${!ownerPermissionsAppName[@]}";
do

    debase=$(echo $key | base64 -d)

    owner=$(echo -n $debase | awk -F ";" '{print $1}')
    permissionsResourceDisplayName=$(echo -n $debase | awk -F ";" '{print $2}')
    permissionName=$(echo -n $debase | awk -F ";" '{print $3}')
    permissionDesc=$(echo -n $debase | awk -F ";" '{print $4}')
    permissionType=$(echo -n $debase | awk -F ";" '{print $5}')
    permissionId=$(echo -n $debase | awk -F ";" '{print $6}')
    # appPassSecrets=$(echo -n $debase | awk -F ";" '{print $7}')
    # appKeySecrets=$(echo -n $debase | awk -F ";" '{print $8}')

    dangerousPermissions=$(getDangerousApiPermissions $permissionId)
    permissionIsDangerous=$(echo $dangerousPermissions | cut -d' ' -f1)
    dangerousDescription=$(echo $dangerousPermissions | cut -d' ' -f2- -s)

    echoArr=("$owner" "$permissionsResourceDisplayName" "$permissionName" "$permissionDesc" "$permissionType" "$permissionId" "${ownerPermissionsAppId[$key]}" "${ownerPermissionsAppName[$key]}" "$permissionIsDangerous" "$dangerousDescription") #"$appPassSecrets" "$appKeySecrets")

    printRow false $outputFilenameOwners true "${echoArr[@]}"

done