<#
.SYNOPSIS
    Assembles a release ZIP file containing the program and its dependencies.

.PARAMETER NoBuild
    If specified, the script will skip the build steps for both 'anticheat_user'
    and 'game' projects. It will only collect pre-existing build artifacts.

.EXAMPLE
    .\build_release.ps1

.EXAMPLE
    .\build_release.ps1 -NoBuild
#>

param (
    [switch]$NoBuild
)

# --- Configuration & Global Variables ---
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$AnticheatUserDir = Join-Path $ScriptDir "anticheat_user"
$AnticheatKernelDir = Join-Path $ScriptDir "anticheat_kernel"
$GameDir = Join-Path $ScriptDir "game"
$ReleaseZipPath = Join-Path $ScriptDir "release.zip"

# Use a Dictionary to store unique file paths: Key=SourceFullPath, Value=PSCustomObject(Source, TargetInZip)
$CollectedFilesDict = New-Object 'System.Collections.Generic.Dictionary[string, object]'

# --- Helper Functions ---

function Log {
    param([string]$Message)
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Message"
}

function ParseEnvFile {
    param([string]$FilePath)
    Log "Parsing environment file: $FilePath"
    if (-not (Test-Path $FilePath)) {
        Log "Error: Environment file not found at $FilePath"
        return $false
    }
    Get-Content $FilePath | ForEach-Object {
        # Match lines like KEY=VALUE, ignoring comments and leading/trailing whitespace
        if ($_ -match '^\s*([^#=\s]+)\s*=\s*(.*)$') {
            $key = $Matches[1]
            $value = $Matches[2].Trim("`"") # Remove quotes if present
            Log "  Setting env: $key = '$value'"
            [System.Environment]::SetEnvironmentVariable($key, $value, [System.EnvironmentVariableTarget]::Process)
        }
    }
    return $true
}

function AddFilesToCollection {
    param(
        [Parameter(Mandatory=$true)][string[]]$SourcePaths,
        [Parameter(Mandatory=$false)][string]$ZipRelativePath = "" # Optional sub-directory within the ZIP
    )
    foreach ($path in $SourcePaths) {
        if (Test-Path $path) {
            $fileName = Split-Path -Leaf $path
            $targetPathInZip = if ($ZipRelativePath) { Join-Path $ZipRelativePath $fileName } else { $fileName }
            # Use FullyQualifiedName to ensure consistent paths for comparisons in Dictionary key
            $fullSourcePath = (Get-Item $path).FullName

            $fileObject = [pscustomobject]@{
                Source = $fullSourcePath
                Target = $targetPathInZip
            }

            if (-not $CollectedFilesDict.ContainsKey($fileObject.Source)) {
                $CollectedFilesDict.Add($fileObject.Source, $fileObject)
                Log "  Adding file to collection: '$fullSourcePath' -> '$targetPathInZip'"
            } else {
                Log "  Skipping duplicate file in collection: '$fullSourcePath'"
            }
        } else {
            Log "  Warning: File not found, skipping: $path"
        }
    }
}

# --- Main Script Logic ---

Log "Starting release assembly script."
Log "  -NoBuild flag: $NoBuild"

# 1. Process Anticheat User Component
Log "`n--- Processing Anticheat User Component ---"
Push-Location $AnticheatUserDir

# Load .env-release and set environment variables
if (-not (ParseEnvFile ".env-release")) {
    Log "Failed to load .env-release. Please ensure it exists and is correctly formatted. Exiting."
    Pop-Location
    Exit 1
}

# Check for pkgconf binary availability
$PkgConfigPath = $env:PKG_CONFIG
$UsePkgConfig = $false
if (-not $PkgConfigPath) {
    Log "Warning: PKG_CONFIG environment variable not set. Cannot use pkgconf binary for dependency resolution."
} elseif (-not (Test-Path $PkgConfigPath)) {
    Log "Warning: PKG_CONFIG points to '$PkgConfigPath', but the binary was not found."
} else {
    Log "Using pkgconf binary: $PkgConfigPath"
    $UsePkgConfig = $true
}

# Perform build if not --no-build
if (-not $NoBuild) {
    Log "Building anticheat_user..."
    try {
        & meson compile -C releasedir | Out-Host # Pipe to Out-Host to see output in real-time
        if ($LASTEXITCODE -ne 0) { throw "Meson compile failed." }
        Log "Anticheat_user build complete."
    } catch {
        Log "Error building anticheat_user: $_"
        Pop-Location
        Exit 1
    }
} else {
    Log "Skipping anticheat_user build (--no-build specified)."
}

# Collect anticheat_user and TSS.CPP DLLs
Log "Collecting anticheat_user and TSS.CPP DLLs..."
$anticheatReleasedir = Join-Path $PWD "releasedir" # Use $PWD as it's current location after Push-Location
AddFilesToCollection (Join-Path $anticheatReleasedir "anticheat_user.dll")
AddFilesToCollection (Join-Path $anticheatReleasedir "subprojects\TSS.CPP\tss_cpp.dll")

# Dependency resolution for protobuf and libsodium using pkgconf
$ProcessedPackages = New-Object System.Collections.Generic.HashSet[string] # To prevent infinite recursion

function ResolveAndCollectPkgConfDlls {
    param([string]$PackageName)

    if ([string]::IsNullOrWhiteSpace($PackageName) -or $ProcessedPackages.Contains($PackageName)) {
        return
    }
    $ProcessedPackages.Add($PackageName) | Out-Null

    Log "  Resolving DLLs for package: $PackageName"

    try {
        # Get relevant directories for the package
        $libdir = (Invoke-Expression "& `"$PkgConfigPath`" --variable=libdir $PackageName" -ErrorAction SilentlyContinue | Out-String).Trim()
        $bindir = (Invoke-Expression "& `"$PkgConfigPath`" --variable=bindir $PackageName" -ErrorAction SilentlyContinue | Out-String).Trim()
        
        if ([string]::IsNullOrWhiteSpace($bindir)) {
            $prefix = (Invoke-Expression "& `"$PkgConfigPath`" --variable=prefix $PackageName" -ErrorAction SilentlyContinue | Out-String).Trim()
            if (-not [string]::IsNullOrWhiteSpace($prefix)) {
                $bindir = Join-Path $prefix "bin"
                Log "      Derived bindir: $bindir (from prefix: $prefix)"
            }
        }
        if ([string]::IsNullOrWhiteSpace($libdir) -and [string]::IsNullOrWhiteSpace($bindir)){
             Log "    Warning: Could not get libdir or bindir for '$PackageName'. Skipping DLL collection for this package."
             return
        }

        # Get the 'Libs:' info, looking for -l flags
        $libsOutput = (Invoke-Expression "& `"$PkgConfigPath`" --libs $PackageName" -ErrorAction SilentlyContinue | Out-String).Trim()

        # Extract DLL names from -l flags. Assuming -llibname -> libname.dll or -lname -> name.dll
        $dllNamePattern = '^-l(lib\S+)$|^-l(\S+)$' # Matches -llibname or -lname (S+ allows for names like libprotobuf-lite)
        $libsOutput -split '\s+' | ForEach-Object {
            if ($_ -match $dllNamePattern) {
                $dllBaseName = if ($Matches[1]) { $Matches[1] } else { $Matches[2] }
                
                if (-not [string]::IsNullOrWhiteSpace($dllBaseName)) {
                    $dllFound = $false
                    # Prefer bindir, then libdir
                    if (-not [string]::IsNullOrWhiteSpace($bindir)) {
                        $dllPath = Join-Path $bindir "$dllBaseName.dll"
                        if (Test-Path $dllPath) {
                            AddFilesToCollection $dllPath
                            Log "      Found DLL in bindir: $dllPath"
                            $dllFound = $true
                        }
                    }
                    if (-not $dllFound -and (-not [string]::IsNullOrWhiteSpace($libdir))) {
                        $dllPath = Join-Path $libdir "$dllBaseName.dll"
                        if (Test-Path $dllPath) {
                            AddFilesToCollection $dllPath
                            Log "      Found DLL in libdir: $dllPath"
                            $dllFound = $true
                        }
                    }

                    if (-not $dllFound) {
                         Log "      Warning: Expected DLL '$dllBaseName.dll' not found in bindir ('$bindir') or libdir ('$libdir') for package '$PackageName'."
                    }
                }
            }
        }

        # Recursively resolve dependencies (Requires and Requires.private)
        $requiredPackagesOutput = (Invoke-Expression "& `"$PkgConfigPath`" --print-requires --print-requires-private $PackageName" -ErrorAction SilentlyContinue | Out-String).Trim()
        $requiredPackagesOutput -split '\s+' | ForEach-Object {
            if (-not [string]::IsNullOrWhiteSpace($_)) { # Ensure we don't process empty strings
                ResolveAndCollectPkgConfDlls $_ # Recursive call
            }
        }
    } catch {
        Log "  Error resolving $PackageName with pkgconf: $_"
    }
}

if ($UsePkgConfig) {
    Log "Collecting recursive dependencies for protobuf and libsodium using pkgconf..."
    ResolveAndCollectPkgConfDlls "protobuf"
    ResolveAndCollectPkgConfDlls "libsodium"
} else {
    Log "Skipping pkgconf dependency resolution. Manual DLL inclusion may be required."
}

Pop-Location # Back to $ScriptDir

# 2. Process Anticheat Kernel Component
Log "`n--- Processing Anticheat Kernel Component ---"
Push-Location $AnticheatKernelDir

# Perform build if not --no-build
if (-not $NoBuild) {
    Log "Building anticheat_kernel..."
    try {
        # adjust the build command as needed; this assumes a Meson build under 'builddir'
        & meson compile -C builddir | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "Meson compile failed in anticheat_kernel." }
        Log "Anticheat_kernel build complete."
    } catch {
        Log "Error building anticheat_kernel: $_"
        Pop-Location
        Exit 1
    }
} else {
    Log "Skipping anticheat_kernel build (--no-build specified)."
}

Log "Collecting kernel driver sys file..."
$kernelBuildDir = Join-Path $PWD "builddir"
AddFilesToCollection (Join-Path $kernelBuildDir "mydriver.sys")

Pop-Location # Back to $ScriptDir

# 2. Process Game Component
Log "`n--- Processing Game Component ---"
Push-Location $GameDir

if (-not $NoBuild) {
    Log "Building game project..."
    try {
        & dotnet build --configuration Release | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "dotnet build failed." }
        Log "Game build complete."
    } catch {
        Log "Error building game: $_"
        Pop-Location
        Exit 1
    }
} else {
    Log "Skipping game build (--no-build specified)."
}

Log "Collecting game files from bin\Release\net9.0\..."
# Correctly join path components relative to current directory ($GameDir)
$gameBuildOutputDir = Join-Path $PWD (Join-Path (Join-Path "bin" "Release") "net9.0")

if (Test-Path $gameBuildOutputDir) {
    Get-ChildItem -Path $gameBuildOutputDir -File -Recurse:$false | ForEach-Object {
        if ($_.Extension -ne ".pdb") {
            AddFilesToCollection $_.FullName
        } else {
            Log "  Skipping PDB file: $($_.Name)"
        }
    }
} else {
    Log "  Warning: Game build output directory not found: $gameBuildOutputDir"
}


Pop-Location # Back to $ScriptDir

# 3. Assemble ZIP file
Log "`n--- Assembling release.zip ---"

if (Test-Path $ReleaseZipPath) {
    Remove-Item $ReleaseZipPath -Force -ErrorAction SilentlyContinue
    Log "Removed existing $ReleaseZipPath."
}

if ($CollectedFilesDict.Count -eq 0) {
    Log "No files collected. ZIP file will not be created."
    # Exit 0 here as it might be intentional if --no-build and no files exist
    Log "Script finished: No files to ZIP."
    Exit 0
}

try {
    $tempZipDir = Join-Path $env:TEMP "temp_release_zip_staging_$(Get-Random)"
    if (Test-Path $tempZipDir) { Remove-Item $tempZipDir -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path $tempZipDir | Out-Null
    Log "Staging files in temporary directory: $tempZipDir"

    foreach ($fileObj in $CollectedFilesDict.Values) {
        $sourcePath = $fileObj.Source
        $targetZipPath = $fileObj.Target
        $targetFilePathInStaging = Join-Path $tempZipDir $targetZipPath

        $targetFileDirInStaging = Split-Path $targetFilePathInStaging
        if (-not (Test-Path $targetFileDirInStaging)) {
            New-Item -ItemType Directory -Path $targetFileDirInStaging -Force | Out-Null
        }

        Log "  Copying '$sourcePath' to staging '$targetFilePathInStaging'"
        Copy-Item -Path $sourcePath -Destination $targetFilePathInStaging -Force
    }

    Log "Creating ZIP archive: $ReleaseZipPath"
    Compress-Archive -Path (Join-Path $tempZipDir "*") -DestinationPath $ReleaseZipPath -Force -ErrorAction Stop

    Log "Cleaning up temporary staging directory: $tempZipDir"
    Remove-Item $tempZipDir -Recurse -Force -ErrorAction SilentlyContinue

    Log "Release ZIP file created successfully at $ReleaseZipPath"
} catch {
    Log "Error creating ZIP file: $_"
    if (Test-Path $tempZipDir) { Remove-Item $tempZipDir -Recurse -Force -ErrorAction SilentlyContinue }
    Exit 1
}

Log "`nScript finished."
