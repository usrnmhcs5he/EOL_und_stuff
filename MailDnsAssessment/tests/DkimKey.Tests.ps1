# DKIM key decoding. The keys below are throwaway public keys generated for these tests.

Describe 'Get-DkimKeyInfo' {
    BeforeAll {
        . (Join-Path $PSScriptRoot '_TestHelpers.ps1')
        . (Join-Path $PSScriptRoot 'Fixtures.ps1')
    }

    It 'derives the RSA modulus length from SubjectPublicKeyInfo' {
        Assert-Equal 512 (Get-DkimKeyInfo $FixtureKeys.Spki512).Bits
        Assert-Equal 1024 (Get-DkimKeyInfo $FixtureKeys.Spki1024).Bits
        Assert-Equal 2048 (Get-DkimKeyInfo $FixtureKeys.Spki2048).Bits
        Assert-Equal 4096 (Get-DkimKeyInfo $FixtureKeys.Spki4096).Bits
    }

    It 'reports the SPKI format and RSA type' {
        $k = Get-DkimKeyInfo $FixtureKeys.Spki2048
        Assert-Equal 'RSA' $k.KeyType
        Assert-Equal 'SPKI' $k.Format
    }

    It 'accepts a bare PKCS#1 RSAPublicKey' {
        $k = Get-DkimKeyInfo $FixtureKeys.Pkcs1_2048
        Assert-Equal 2048 $k.Bits
        Assert-Equal 'PKCS1' $k.Format
    }

    It 'ignores whitespace inside p=' {
        $spaced = $FixtureKeys.Spki1024.Insert(40, ' ').Insert(100, "`t")
        Assert-Equal 1024 (Get-DkimKeyInfo $spaced).Bits
    }

    It 'counts bits from the first significant byte, not from the base64 length' {
        # SEQUENCE { INTEGER 0x01FF, INTEGER 3 } -> 9-bit modulus
        $b64 = [Convert]::ToBase64String([byte[]](0x30, 0x07, 0x02, 0x02, 0x01, 0xFF, 0x02, 0x01, 0x03))
        Assert-Equal 9 (Get-DkimKeyInfo $b64).Bits
    }

    It 'agrees with the platform API (ImportSubjectPublicKeyInfo on PowerShell 7, PublicKey on 5.1)' {
        foreach ($key in @($FixtureKeys.Spki1024, $FixtureKeys.Spki2048, $FixtureKeys.Spki4096, $FixtureKeys.Pkcs1_2048)) {
            $k = Get-DkimKeyInfo $key
            Assert-True ($k.PlatformMethod -ne 'unavailable') "platform path failed for a $($k.Bits)-bit key"
            Assert-Equal $k.Bits $k.PlatformBits $k.PlatformMethod
        }
        $expected = if ($PSVersionTable.PSEdition -eq 'Core') { 'RSA.ImportSubjectPublicKeyInfo' } else { 'X509Certificates.PublicKey' }
        Assert-Equal $expected (Get-DkimKeyInfo $FixtureKeys.Spki2048).PlatformMethod
    }

    It 'calls the .NET Framework PublicKey path explicitly' {
        $bytes = [Convert]::FromBase64String($FixtureKeys.Pkcs1_2048)
        $oid = New-Object System.Security.Cryptography.Oid('1.2.840.113549.1.1.1')
        $params = New-Object System.Security.Cryptography.AsnEncodedData($oid, [byte[]](5, 0))
        $key = New-Object System.Security.Cryptography.AsnEncodedData($oid, $bytes)
        $pk = New-Object System.Security.Cryptography.X509Certificates.PublicKey($oid, $params, $key)
        $bits = if ($PSVersionTable.PSEdition -eq 'Core') { $pk.GetRSAPublicKey().KeySize } else { $pk.Key.KeySize }
        Assert-Equal 2048 $bits
    }

    It 'reports Ed25519 keys as non-RSA' {
        $raw = Get-DkimKeyInfo -PublicKey $FixtureKeys.Ed25519Raw -KeyType 'ed25519'
        Assert-Equal 'Ed25519' $raw.KeyType
        Assert-Equal 256 $raw.Bits
        Assert-Equal 'Ed25519' (Get-DkimKeyInfo $FixtureKeys.Ed25519Spki).KeyType
    }

    It 'reports an empty p= as revoked' {
        Assert-True (Get-DkimKeyInfo '').Revoked
    }

    It 'reports undecodable keys' {
        Assert-True ([bool](Get-DkimKeyInfo 'not*base64').Error)
        Assert-True ([bool](Get-DkimKeyInfo 'AAAA').Error)
    }
}
