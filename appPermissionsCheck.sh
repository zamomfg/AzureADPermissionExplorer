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

    # echo "$value"";""$appId"";""$appName"
    # echo $base

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

# check requirements
azReq=$(command -v az)
if [ $? -ne 0 ] ; then
    echo 'Error: "az" command not found.This script require the Azure CLI to be installed'
    return 2
fi

delimiter=";"

outputFilenameApps="apps_output.csv"
outputFilenameOwners="owners_output.csv"

appHeader=("appId" "appDisplayName" "permissionResource" "permissionName" "permissionDescription" "permissionId" "appOwners")
printRow true $outputFilenameApps false "${appHeader[@]}"

ownerHeader=("userPrincipalName" "permissionResource" "permissionName" "permissionDescription" "permissionId" "appId" "appDisplayName")
printRow false $outputFilenameOwners false "${ownerHeader[@]}"

if [ -n "$1" ]
then
	appList=$1
else
	appList=$(az ad app list --all --query "[*].appId" --output tsv)
fi

for id in $appList
do

    appDisplayName=$(az ad app show --id $id --query "displayName" | sed 's/\"//g')
    appPermissions=$(az ad app permission list --id $id --query "[*]" | jq -r '.[] | .resourceAppId + ";" + .resourceAccess[].id + ";" + .resourceAccess[].type' | tr ";" "$delimiter")
    appOwners=$(az ad app owner list --id $id --query "[*].userPrincipalName" | jq -r '. | join(" ")')

    for permissions in $appPermissions
    do
        resourceId=$(echo $permissions | awk -F $delimiter '{ print $1 }')
        permissionId=$(echo $permissions | awk -F $delimiter '{ print $2 }')
        permissionType=$(echo $permissions | awk -F $delimiter '{ print $3 }')

        permissionsRequest=$(az rest --url "https://graph.microsoft.com/v1.0/servicePrincipals?\$filter=appId eq '$resourceId'&\$select=appId, displayName, appRoles, oauth2PermissionScopes")
        permissionsResourceDisplayName=$(echo $permissionsRequest | jq --arg id $resourceId -r '.value[]  |  select (.appId==$id) | .displayName')
        permissionName=$(echo $permissionsRequest | jq --arg permId $permissionId -r '.value[] | .appRoles[], .oauth2PermissionScopes[] | select (.id==$permId) | .value')
        permissionDesc=$(echo $permissionsRequest | jq --arg permId $permissionId -r '.value[] | .appRoles[], .oauth2PermissionScopes[] | select (.id==$permId)  | .description +""+ .adminConsentDescription')

        echoArr=("$id" "$appDisplayName" "$permissionsResourceDisplayName" "$permissionName" "$permissionDesc" "$permissionId" "$appOwners")
        printRow true $outputFilenameApps true "${echoArr[@]}"

        # echo $permissionsRequest > "$permissions.json"

        for owner in $appOwners
        do
            echoArr=("$owner" "$permissionsResourceDisplayName" "$permissionName" "$permissionDesc" "$permissionId")
            ownerString=$(printRow true $outputFilenameOwners "dontPrint" "${echoArr[@]}")
 
            addToOwnerDict "$ownerString" "$id" "$appDisplayName"
            echo "$ownerString"";""$id"";""$appDisplayName" >> testfile.csv
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
    permissionId=$(echo -n $debase | awk -F ";" '{print $5}')
    echoArr=("$owner" "$permissionsResourceDisplayName" "$permissionName" "$permissionDesc" "$permissionId" "${ownerPermissionsAppId[$key]}" "${ownerPermissionsAppName[$key]}")

    printRow false $outputFilenameOwners true "${echoArr[@]}"

done