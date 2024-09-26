# Implement your module commands in this script.
class KRCredential {
    [string]$Name
    [string]$UserName
    hidden [string]$EncryptedPassword
    [string]$Domain=[string]::Empty

    KRCredential([string]$name, [PSCredential]$credential, [byte[]]$key){
        $this.Name = $name
        $this.UserName = $credential.UserName
        $this.EncryptedPassword = $credential.Password | ConvertFrom-SecureString -Key $key
    }

    KRCredential([string]$name, [PSCredential]$credential, [byte[]]$key, [string]$domain_url){
        $this.Name = $name
        $this.UserName = $credential.UserName
        $this.EncryptedPassword = $credential.Password | ConvertFrom-SecureString -Key $key
        $this.Domain = $domain_url
    }

    KRCredential($credObj){
        $this.Name = $credObj.Name
        $this.UserName = $credObj.UserName
        $this.EncryptedPassword = $credObj.EncryptedPassword
        $this.Domain = $credObj.Domain
    }

    [System.Security.SecureString] GetSecurePassword([byte[]]$key){
        return ($this.EncryptedPassword | ConvertTo-SecureString -Key $key)
    }

    [string] GetUnsecurePassword([byte[]]$key){
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($this.GetSecurePassword($key))
        $UnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR) | Out-Null
        return $UnsecurePassword
    }

    [pscredential] GetCredential([byte[]]$key){
        return [pscredential]::new($this.UserName, $this.GetSecurePassword())
    }

}

class KeyRing {

    [string]$Name
    [string]$Path
    [int]$ByteLength
    [string]$KeyPath
    [byte[]]$Key
    $Credentails

    KeyRing([string]$name, [string]$projDir, [int]$byteLength, [string]$keyDir){
        $this.Name = $name
        $this.Path = Join-Path $projDir "$($this.Name).krg"
        $this.ByteLength = $byteLength
        $this.KeyPath = Join-Path $keyDir "$($this.Name).key"
        $this.CreateKey()
        $this.ImportKey()
        $this.Credentails = New-Object System.Collections.Generic.List[KRCredential]
        $this.ExportKeyRing()
    }

    KeyRing([string]$keyRingPath){
        $obj = Get-Content $keyRingPath -Raw | ConvertFrom-Json
        $this.Name = $obj.Name
        $this.Path = $keyRingPath
        $this.ByteLength = $obj.ByteLength
        $this.KeyPath = $obj.KeyPath
        if($null -eq $obj.Credentails -or $this.Credentails.Count -lt 1){
            $this.Credentails = New-Object System.Collections.Generic.List[KRCredential]
        }else{
            $obj.Credentails | ForEach-Object {
                $this.AddKRCredential([KRCredential]::new($_)) | Out-Null
            }
        }
        $this.ImportKey()

    }

    hidden [void] CreateKey(){
        $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $buffer = New-Object byte[] $this.ByteLength
        $random.GetBytes($buffer)
        $buffer | Set-Content $this.KeyPath
    }

    [void] RotateKey($byteLength=$this.ByteLength, $newKeyDir=[string]::Empty){
        if($newKeyDir -eq [string]::Empty){
            $newKeyDir = [System.IO.Path]::GetDirectoryName($this.KeyPath)
        }
        $this.KeyPath = Join-Path $newKeyDir "$($this.Name).key"
        if(Test-Path $this.KeyPath){
            Remove-Item $this.KeyPath
        }
        $this.ImportKey()
        $oldkey = $this.Key
        $this.CreateKey()
        $this.ImportKey()

        $this.Credentails.ForEach({
            $_.EncryptedPassword = $_.GetSecurePassword($oldkey) | ConvertFrom-SecureString -Key $KeyRing.Key
        })

        $this.ExportKeyRing()
    }

    hidden [void] ImportKey(){
        $this.Key = [byte[]](Get-Content $this.KeyPath)
    }

    [void] ExportKeyRing(){
        $this | Select-Object -Property Name, Path, ByteLength, KeyPath, Credentails | ConvertTo-Json | Set-Content $this.Path
    }

    [bool] CredentailExists([string]$name){
        if($this.Credentails.Count -gt 0){
            return $name -in ($this.Credentails | ForEach-Object{$_.Name})
        }else{
            return $false
        }
    }

    [void] AddKRCredential([KRCredential]$krCred){
        if($this.CredentailExists($krCred.Name)){
            throw [System.Management.Automation.MethodInvocationException] "Credentail already exists for name $($krCred.Name)"
        }
        $this.Credentails.Add($krCred)| Out-Null
    }


}

[KeyRing[]]$env:Keychain = New-Object 'System.Collections.Generic.List[KeyRing]'

function New-KeyRing {
    [CmdletBinding()]
    param (
        # Parameter help description
        [Parameter(Mandatory)]
        [ValidateNotNullOrWhiteSpace()]
        [string]
        $Name,
        # Parameter help description
        [Parameter(Mandatory=$false)]
        [ValidateSet(16, 24, 32)]
        [int]
        $ByteLength=32,
        # Parameter help description
        [Parameter(Mandatory=$false)]
        [string]
        $Directory=".\",
        # Parameter help description
        [Parameter(Mandatory)]
        [string]
        $KeyDirectory
    )

    begin {
        if(-not(Test-Path $Directory)){
            throw [System.IO.FileNotFoundException] "Directory $Directory does not exist"
        }
        if(-not(Test-Path $KeyDirectory)){
            throw [System.IO.FileNotFoundException] "Directory $KeyDirectory does not exist"
        }
    }

    process {
        return [KeyRing]::new($Name, $Directory, $ByteLength, $KeyDirectory)
    }

    end {

    }
}

function Add-KRCredential {
    [CmdletBinding()]
    param (
        # Parameter help description
        [Parameter(Mandatory)]
        $KeyRing,
        # Parameter help description
        [Parameter(Mandatory)]
        [ValidateNotNullOrWhiteSpace()]
        [string]
        $Name,
        # Parameter help description
        [Parameter(Mandatory)]
        [pscredential]
        $Credential,
        # Parameter help description
        [Parameter(Mandatory=$false)]
        [string]
        $Domain_URL,
        # Parameter help description
        [Parameter(Mandatory=$false)]
        [switch]
        $SaveKeyRing
    )

    begin {

    }

    process {
        if($Domain_URL){
            $krCred = [KRCredential]::new($Name, $Credential, $KeyRing.Key, $Domain_URL)
        }else{
            $krCred = [KRCredential]::new($Name, $Credential, $KeyRing.Key)
        }
        $KeyRing.AddKRCredential($krCred)
        if($SaveKeyRing){
            $KeyRing.ExportKeyRing()
        }
    }

    end {

    }
}

# Export only the functions using PowerShell standard verb-noun naming.
# Be sure to list each exported functions in the FunctionsToExport field of the module manifest file.
# This improves performance of command discovery in PowerShell.
Export-ModuleMember -Function *-*


$keydir = "C:\Users\roder\Code\keys"
$kr = New-KeyRing -Name "TestKR" -ByteLength 32 -KeyDirectory $keydir

$username = 'Username'
$password = 'Password' | ConvertTo-SecureString -AsPlainText -Force
$credential = [PSCredential]::New($username,$password)

Add-KRCredential -KeyRing $kr -Name "TestCredentail" -Credential $credential -SaveKeyRing