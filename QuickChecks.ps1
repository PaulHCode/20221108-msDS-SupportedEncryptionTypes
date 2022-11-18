<#
.Synopsis
   Turns the integer stored in msDS-SupportedEncryptionTypes into a human readable value
.DESCRIPTION
   Turns the integer stored in msDS-SupportedEncryptionTypes into a human readable value
   For more info on the encryption types: https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/decrypting-the-selection-of-supported-kerberos-encryption-types/ba-p/1628797
.EXAMPLE
   Get-ETypeDefiniton 7
.PARAMETER msDSSupportedEncryptionTypes
    Returns an array of results indicating the supported encryption types
.PARAMETER AsString
    Returns the result as a comma delimited string
.NOTES
    Author:  Paul Harrison
#>
function Get-ETypeDefinition {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [int]$msDSSupportedEncryptionTypes,
        [switch] $AsString
    )
    Begin {
        $ETypes = [HASHTABLE]@{
            0  = 'Not defined - defaults to RC4_HMAC_MD5'
            1  = 'DES_CBC_CRC'
            2  = 'DES_CBC_MD5'
            4  = 'RC4'
            8  = 'AES 128'
            16 = 'AES 256'
        }
    }
    Process {
        $Types = $ETypes.keys | ForEach-Object {
            If ([int]($msDSSupportedEncryptionTypes -band [int]$_) -ne 0) {
                $ETypes[[int]$_]
            }
        }
        If (0 -eq $msDSSupportedEncryptionTypes) {
            $Types = $ETypes[0]
        }
        If ($AsString) {
            $Types -join (',')
        }
        Else {
            $Types
        }
    }
    End {
    }
}


#Get all impacted AD objects
Get-ADObject -Filter * -Properties msDS-SupportedEncryptionTypes | `
        Select-Object name, objectClass, 'msDS-SupportedEncryptionTypes', @{N = 'EncryptionTypes'; E = { Get-ETypeDefinition -msDSSupportedEncryptionTypes ($_.'msDS-SupportedEncryptionTypes') } }, @{N = 'EncryptionTypesAsString'; E = { Get-ETypeDefinition -msDSSupportedEncryptionTypes ($_.'msDS-SupportedEncryptionTypes') -AsString } } | `
            Select-Object name, objectClass, EncryptionTypes, @{N = 'HasRC4OrIsBlank'; E = { $_.EncryptionTypesAsString -like "*RC4*" } } | `
                Where-Object { -not $_.HasRC4OrIsBlank }

#Summary of msDS-SupportedEncryptionTypes for all AD objects
Get-ADObject -Filter * -Properties msDS-SupportedEncryptionTypes | Group-Object msDS-SupportedEncryptionTypes | Select-Object count, name

#Summary of msDS-SupportedEncryptionTypes for all computer objects - human readable
Get-ADObject -Filter * -Properties msDS-SupportedEncryptionTypes | `
        Group-Object msDS-SupportedEncryptionTypes | `
            Select-Object count, name, 'msDS-SupportedEncryptionTypes', @{N = 'EncryptionTypes'; E = { Get-ETypeDefinition -msDSSupportedEncryptionTypes ($_.Name) } }, @{N = 'EncryptionTypesAsString'; E = { Get-ETypeDefinition -msDSSupportedEncryptionTypes ($_.Name) -AsString } } | `
                Select-Object count, name, EncryptionTypes, @{N = 'HasRC4OrIsBlank'; E = { $_.EncryptionTypesAsString -like "*RC4*" } } 

##
#Separate categories for investigating each object type are below. It is simply passing a different object type over the same pipeline
##

#Get computer objects
$computers = Get-ADComputer -Filter * -Properties msDS-SupportedEncryptionTypes

#Summary of msDS-SupportedEncryptionTypes for all computer objects
$computers | Group-Object msDS-SupportedEncryptionTypes | Select-Object count, name

#Summary of msDS-SupportedEncryptionTypes for all computer objects - human readable
$computers | `
        Group-Object msDS-SupportedEncryptionTypes | `
            Select-Object count, name, 'msDS-SupportedEncryptionTypes', @{N = 'EncryptionTypes'; E = { Get-ETypeDefinition -msDSSupportedEncryptionTypes ($_.Name) } }, @{N = 'EncryptionTypesAsString'; E = { Get-ETypeDefinition -msDSSupportedEncryptionTypes ($_.Name) -AsString } } | `
                Select-Object count, name, EncryptionTypes, @{N = 'HasRC4OrIsBlank'; E = { $_.EncryptionTypesAsString -like "*RC4*" } } 

#List all computers that will be impacted
$computers | `
        Select-Object name, 'msDS-SupportedEncryptionTypes', @{N = 'EncryptionTypes'; E = { Get-ETypeDefinition -msDSSupportedEncryptionTypes ($_.'msDS-SupportedEncryptionTypes') } }, @{N = 'EncryptionTypesAsString'; E = { Get-ETypeDefinition -msDSSupportedEncryptionTypes ($_.'msDS-SupportedEncryptionTypes') -AsString } } | `
            Select-Object name, EncryptionTypes, @{N = 'HasRC4OrIsBlank'; E = { $_.EncryptionTypesAsString -like "*RC4*" } } | `
                Where-Object { -not $_.HasRC4OrIsBlank }


#Get the gMSAs
$gMSAs = Get-ADServiceAccount -Filter * -Properties msDS-SupportedEncryptionTypes 

#Summary of msDS-SupportedEncryptionTypes for all gMSAs
$gMSAs | Group-Object msDS-SupportedEncryptionTypes | Select-Object count, name

#Summary of msDS-SupportedEncryptionTypes for all gMSAs - human readable
$gMSAs | `
        Group-Object msDS-SupportedEncryptionTypes | `
            Select-Object count, name, 'msDS-SupportedEncryptionTypes', @{N = 'EncryptionTypes'; E = { Get-ETypeDefinition -msDSSupportedEncryptionTypes ($_.Name) } }, @{N = 'EncryptionTypesAsString'; E = { Get-ETypeDefinition -msDSSupportedEncryptionTypes ($_.Name) -AsString } } | `
                Select-Object count, name, EncryptionTypes, @{N = 'HasRC4OrIsBlank'; E = { $_.EncryptionTypesAsString -like "*RC4*" } } 

#List all gMSAs that will be impacted
$gMSAs | `
        Select-Object name, 'msDS-SupportedEncryptionTypes', @{N = 'EncryptionTypes'; E = { Get-ETypeDefinition -msDSSupportedEncryptionTypes ($_.'msDS-SupportedEncryptionTypes') } }, @{N = 'EncryptionTypesAsString'; E = { Get-ETypeDefinition -msDSSupportedEncryptionTypes ($_.'msDS-SupportedEncryptionTypes') -AsString } } | `
            Select-Object name, EncryptionTypes, @{N = 'HasRC4OrIsBlank'; E = { $_.EncryptionTypesAsString -like "*RC4*" } } | `
                Where-Object { -not $_.HasRC4OrIsBlank }


#Get the user objects
$users = Get-ADUser -Filter * -Properties msDS-SupportedEncryptionTypes

#Summary of msDS-SupportedEncryptionTypes for all user objects
$users | Group-Object msDS-SupportedEncryptionTypes | Select-Object count, name

#Summary of msDS-SupportedEncryptionTypes for all user objects
$users | `
        Group-Object msDS-SupportedEncryptionTypes | `
            Select-Object count, name, 'msDS-SupportedEncryptionTypes', @{N = 'EncryptionTypes'; E = { Get-ETypeDefinition -msDSSupportedEncryptionTypes ($_.Name) } }, @{N = 'EncryptionTypesAsString'; E = { Get-ETypeDefinition -msDSSupportedEncryptionTypes ($_.Name) -AsString } } | `
                Select-Object count, name, EncryptionTypes, @{N = 'HasRC4OrIsBlank'; E = { $_.EncryptionTypesAsString -like "*RC4*" } } 

#List all users that will be impacted
$users | `
        Select-Object name, 'msDS-SupportedEncryptionTypes', @{N = 'EncryptionTypes'; E = { Get-ETypeDefinition -msDSSupportedEncryptionTypes ($_.'msDS-SupportedEncryptionTypes') } }, @{N = 'EncryptionTypesAsString'; E = { Get-ETypeDefinition -msDSSupportedEncryptionTypes ($_.'msDS-SupportedEncryptionTypes') -AsString } } | `
            Select-Object name, EncryptionTypes, @{N = 'HasRC4OrIsBlank'; E = { $_.EncryptionTypesAsString -like "*RC4*" } } | `
                Where-Object { -not $_.HasRC4OrIsBlank }

