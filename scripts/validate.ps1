$ErrorActionPreference = "Stop"

function Invoke-CargoCheck {
    param([string[]]$CargoArguments)
    & cargo @CargoArguments
    if ($LASTEXITCODE -ne 0) { throw "Cargo validation failed: $CargoArguments" }
}

Invoke-CargoCheck -CargoArguments @("fmt", "--all", "--", "--check")
Invoke-CargoCheck -CargoArguments @("clippy", "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings")
Invoke-CargoCheck -CargoArguments @("test", "--workspace", "--all-features", "--locked")
Invoke-CargoCheck -CargoArguments @("check", "-p", "winptap", "--no-default-features")
foreach ($feature in @("pktmon", "native", "tokio", "pktmon,tokio", "native,tokio")) {
    Invoke-CargoCheck -CargoArguments @("check", "-p", "winptap", "--no-default-features", "--features", $feature)
}
Invoke-CargoCheck -CargoArguments @("doc", "--workspace", "--all-features", "--no-deps")

