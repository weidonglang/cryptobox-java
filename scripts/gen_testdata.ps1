# Generate testdata files for cryptobox-java
param()

$targetDir = "testdata"

# Generate bad_magic.crbx
$badMagic = New-Object System.Collections.ArrayList
$badMagic.AddRange([System.Text.Encoding]::ASCII.GetBytes('XXXX')) | Out-Null
$badMagic.AddRange([byte[]]@(0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x10)) | Out-Null
$salt = 1..16 | ForEach-Object { [byte]$_ }
$badMagic.AddRange($salt) | Out-Null
$badMagic.AddRange([byte[]]@(0x00, 0x0c)) | Out-Null
$iv = 1..12 | ForEach-Object { [byte]$_ }
$badMagic.AddRange($iv) | Out-Null
$badMagic.AddRange([byte[]]@(0x00, 0x00, 0x00, 0x10)) | Out-Null
$ct = 1..16 | ForEach-Object { [byte]$_ }
$badMagic.AddRange($ct) | Out-Null
[System.IO.File]::WriteAllBytes("$targetDir/invalid_containers/bad_magic.crbx", $badMagic.ToArray())
Write-Host "Created bad_magic.crbx"

# Generate truncated.crbx (only header bytes)
$truncated = [byte[]]@(0x43, 0x52, 0x42, 0x58, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x10, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07)
[System.IO.File]::WriteAllBytes("$targetDir/invalid_containers/truncated.crbx", $truncated)
Write-Host "Created truncated.crbx"

# Generate bad_tag.crbx from sample.crbx
$sample = [System.IO.File]::ReadAllBytes("$targetDir/valid_containers/sample.crbx")
$badTag = New-Object System.Collections.ArrayList
for($i = 0; $i -lt $sample.Length - 1; $i++) {
    $badTag.Add($sample[$i]) | Out-Null
}
$badTag.Add([byte]0xFF) | Out-Null
[System.IO.File]::WriteAllBytes("$targetDir/invalid_containers/bad_tag.crbx", $badTag.ToArray())
Write-Host "Created bad_tag.crbx"

Write-Host "All testdata files created successfully."