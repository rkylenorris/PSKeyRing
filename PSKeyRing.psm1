# Implement your module commands in this script.
class KRCredential {
    [string]$UserName
    [string]$EncryptedPassword
    [string]$Domain=[string]::Empty

    KRCredential([string]$user, [System.Security.SecureString]$pass, [byte[]]$key){
        $this.UserName = $user
        $this.EncryptedPassword = $pass | ConvertFrom-SecureString -Key $key
    }

    KRCredential([string]$user, [System.Security.SecureString]$pass, [byte[]]$key, [string]$domain_url){
        $this.UserName = $user
        $this.EncryptedPassword = $pass | ConvertFrom-SecureString -Key $key
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
        $random | Set-Content $this.KeyPath
    }

    hidden [void] ImportKey(){
        $this.Key = [byte[]](Get-Content $this.KeyPath)
    }

    [void] ExportKeyRing(){
        $this | Select-Object -Property Name, Path, ByteLength, KeyPath, Credentails | ConvertTo-Json | Set-Content $this.Path
    }

    [void] AddCredential([KRCredential]$krCred){
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


# Export only the functions using PowerShell standard verb-noun naming.
# Be sure to list each exported functions in the FunctionsToExport field of the module manifest file.
# This improves performance of command discovery in PowerShell.
Export-ModuleMember -Function *-*
