$ErrorActionPreference = "Stop"

# Build the project in the anticheat_user subdirectory
Push-Location "anticheat_user"
try {
    Write-Output "Running: meson compile -C builddir"
    meson compile -C builddir
    if (-not $?)
    {
        throw "Compiler error"
    }
}
finally { Pop-Location }

# Copy the DLL to the target directory
$sourceDll = "anticheat_user/builddir/anticheat_user.dll"
$destinationDir = "game/bin/debug/net9.0"
$destinationDll = Join-Path $destinationDir "anticheat_user.dll"

Write-Output "Copying $sourceDll to $destinationDll"
Copy-Item $sourceDll $destinationDll -Force

# Run the client interactively in the game subdirectory
Push-Location "game"
try {
    Write-Output "Running: dotnet run -- client 127.0.0.1 9050"
    # Start-Process dotnet -Verb runAs -Wait -ArgumentList "run --no-restore --no-build -- client 127.0.0.1 9050"
    dotnet run --no-restore --no-build -- client 127.0.0.1 9050
    # dotnet run --no-restore --no-build -- client 88.198.202.223 9050
}
finally { Pop-Location }
