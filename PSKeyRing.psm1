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
    [System.Collections.Generic.List[KRCredential]]$Credentails

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
        if($obj.Credentails.Count -gt 0){
            $this.Credentails = $obj.Credentails
        }else{
            $this.Credentails = New-Object System.Collections.Generic.List[KRCredential]
        }
        $this.ImportKey()

    }

    hidden [void] CreateKey(){
        $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $buffer = New-Object byte[] $this.ByteLength
        $random.GetBytes($buffer)
        $buffer | Set-Content $this.KeyPath
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
        $this.Key.Add($krCred) | Out-Null
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
        [Parameter(Mandatory, ValueFromPipeline=$true)]
        [KeyRing]
        $KeyRing,
        # Parameter help description
        [Parameter(Mandatory)]
        [ValidateNotNullOrWhiteSpace()]
        [string]
        $Name,
        # Parameter help description
        [Parameter(Mandatory)]
        [pscredential]
        $Credentail,
        # Parameter help description
        [Parameter(Mandatory=$false)]
        [string]
        $Domain_URL
    )

    begin {

    }

    process {
        if($Domain_URL){
            $krCred = [KRCredential]::new($Name, $Credentail, $KeyRing.Key, $Domain_URL)
        }else{
            $krCred = [KRCredential]::new($Name, $Credentail, $KeyRing.Key)
        }
        $KeyRing.AddKRCredential($krCred)
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

$krCred = [KRCredential]::new($credential, $kr.Key)