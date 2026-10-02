param([switch]$Test)
$ErrorActionPreference='Stop'
$compiler=Join-Path $env:windir 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if(-not (Test-Path -LiteralPath $compiler)){$compiler=Join-Path $env:windir 'Microsoft.NET\Framework\v4.0.30319\csc.exe'}
if(-not (Test-Path -LiteralPath $compiler)){throw '.NET Framework C# compiler is required'}
$root=Split-Path -Parent $PSScriptRoot
$output=Join-Path $root 'bin\RDPWMaint.exe'
$arguments=@('/nologo','/target:exe','/platform:anycpu','/optimize+','/warn:4','/warnaserror+',('/out:'+$output),'/reference:System.Core.dll','/reference:System.ServiceProcess.dll','/reference:System.Web.Extensions.dll','/reference:Microsoft.CSharp.dll',('/resource:'+(Join-Path $root 'src-installer\resource.res')+',WrapperBundle'),('/resource:'+(Join-Path $root 'res\rdpwrap.ini')+',DefaultIni'))
$arguments+=@(Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.cs' | Select-Object -ExpandProperty FullName)
$arguments+=('/win32manifest:'+(Join-Path $PSScriptRoot 'app.manifest'))
$arguments+=('/resource:'+(Join-Path $root 'LICENSE')+',License')
& $compiler @arguments
if($LASTEXITCODE -ne 0){throw 'Compilation failed'}
if($Test){& $output --self-test;if($LASTEXITCODE -ne 0){throw 'Maintenance tests failed'}}
Write-Host ('Built: '+$output)
