param(
  [string]$BlackSource = "$PSScriptRoot\..\docs\brand\source\ruijing-black-cutout.png",
  [string]$WhiteSource = "$PSScriptRoot\..\docs\brand\source\ruijing-white-cutout.png"
)
# Resize the owner's finished transparent PNGs only. No crop, mask or redrawing.
Add-Type -AssemblyName System.Drawing
$projectRoot = [System.IO.Path]::GetFullPath("$PSScriptRoot\..")
$outputDirectory = Join-Path $projectRoot 'public\assets'
New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
function Export-Size([string]$sourcePath, [string]$name, [int]$pixels) {
  $original = [System.Drawing.Image]::FromFile([System.IO.Path]::GetFullPath($sourcePath))
  $bitmap = [System.Drawing.Bitmap]::new($pixels, $pixels, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
  $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
  try {
    $graphics.Clear([System.Drawing.Color]::Transparent)
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $destination = [System.Drawing.Rectangle]::new(0, 0, $pixels, $pixels)
    $graphics.DrawImage($original, $destination, 0, 0, $original.Width, $original.Height, [System.Drawing.GraphicsUnit]::Pixel)
    $bitmap.Save((Join-Path $outputDirectory $name), [System.Drawing.Imaging.ImageFormat]::Png)
  } finally {
    $graphics.Dispose(); $bitmap.Dispose(); $original.Dispose()
  }
}
Export-Size $BlackSource 'ruijing-logo-black.png' 192
Export-Size $WhiteSource 'ruijing-logo-white.png' 192
Export-Size $BlackSource 'ruijing-icon-black.png' 128
Export-Size $WhiteSource 'ruijing-icon-white.png' 128
