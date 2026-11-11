param (
    [Parameter()]
    [string]$FilePath = "./badmemorylist.txt"
)

# Retrieve the list of bad memory addresses
$badMemoryList = (bcdedit /enum '{badmemory}') |
                 Select-String '^\s+0x' |
                 ForEach-Object { $_.Line.Trim() }

# Save the list to the specified file
$badMemoryList | Out-File -FilePath $FilePath -Encoding UTF8

# Display confirmation message
Write-Host "`nList successfully saved to: $FileName" -ForegroundColor Green
