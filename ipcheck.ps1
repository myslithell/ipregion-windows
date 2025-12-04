<#
.SYNOPSIS
    IPRegion PowerShell (Extended Edition: Gaming & Dev)
#>

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("all", "primary", "custom", "cdn")]
    [string]$Groups = "all",

    [switch]$IPv4Only,
    [switch]$IPv6Only,
    [switch]$JsonOutput,
    [switch]$VerboseLog
)

# --- Config ---
$UserAgent = "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"

# Keys
$Script:NetflixApiKey = "YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm"
$Script:RedditBasicToken = "b2hYcG9xclpZdWIxa2c6"
$Script:OpenAiStatsigKey = "client-zUdXdSTygXJdzoE0sWTkP8GKTVsUMF2IRM7ShVO2JAG"

$Script:ExternalIPv4 = $null
$Script:ExternalIPv6 = $null
$Script:Results = @()

# --- Helpers ---

function Write-Color {
    param([string]$Text, [string]$Color="White", [switch]$NoNewline)
    if ($JsonOutput) { return }
    if ($NoNewline) { Write-Host $Text -ForegroundColor $Color -NoNewline }
    else { Write-Host $Text -ForegroundColor $Color }
}

function Invoke-CurlWrapper {
    param(
        [string]$Url,
        [string]$Method = "GET",
        [hashtable]$Headers = @{},
        [string]$Body = $null,
        [int]$IpVersion = 0,
        [string]$ContentType = "application/json",
        [switch]$ReturnHeaders
    )

    $TempFile = $null
    $CurlArgs = @("-s", "-L", "-k", "--max-time", "10", "-A", $UserAgent)

    if ($IpVersion -eq 4) { $CurlArgs += "-4" }
    if ($IpVersion -eq 6) { $CurlArgs += "-6" }

    if ($ReturnHeaders) { $CurlArgs += "-I" }

    if ($Method -eq "POST") {
        $CurlArgs += "-X"; $CurlArgs += "POST"
        $CurlArgs += "-H"; $CurlArgs += "Content-Type: $ContentType"
        
        if ($Body) { 
            $TempFile = [System.IO.Path]::GetTempFileName()
            $Utf8NoBom = New-Object System.Text.UTF8Encoding $false
            [System.IO.File]::WriteAllText($TempFile, $Body, $Utf8NoBom)
            $CurlArgs += "-d"; $CurlArgs += "@$TempFile"
        }
    } elseif ($Method -eq "HEAD") {
        $CurlArgs += "-I"
    }

    foreach ($key in $Headers.Keys) {
        $CurlArgs += "-H"; $CurlArgs += "${key}: $($Headers[$key])"
    }

    $CurlArgs += $Url

    try {
        if ($VerboseLog) { Write-Host "DEBUG: Executing curl $CurlArgs" -ForegroundColor DarkGray }
        
        $Output = & curl.exe $CurlArgs 2>&1
        
        if ($TempFile -and (Test-Path $TempFile)) { Remove-Item $TempFile -ErrorAction SilentlyContinue }
        if (-not $Output) { return $null }
        if ($Output -is [array]) { $Output = $Output -join "`n" }
        
        if ($ReturnHeaders) { return $Output }

        # JSON Parse Try
        if ($Output.Trim().StartsWith("{") -or $Output.Trim().StartsWith("[")) {
            try { return $Output | ConvertFrom-Json } catch { return $Output }
        }
        return $Output
    } catch {
        if ($TempFile -and (Test-Path $TempFile)) { Remove-Item $TempFile -ErrorAction SilentlyContinue }
        return $null
    }
}

function Get-ExternalIP {
    Write-Color "Checking connectivity..." -Color Cyan
    
    $ServicesV4 = @("http://checkip.amazonaws.com", "https://api.ipify.org", "https://ifconfig.me/ip")
    $ServicesV6 = @("https://api64.ipify.org", "https://icanhazip.com")
    
    if (-not $IPv6Only) {
        foreach ($s in $ServicesV4) {
            $ip = Invoke-CurlWrapper -Url $s -IpVersion 4
            if ($ip -and $ip -match "\d+\.\d+\.\d+\.\d+") {
                $Script:ExternalIPv4 = $ip.Trim()
                Write-Color "Found External IPv4: $Script:ExternalIPv4" -Color DarkGray
                break
            }
        }
    }

    if (-not $IPv4Only) {
        foreach ($s in $ServicesV6) {
            $ip = Invoke-CurlWrapper -Url $s -IpVersion 6
            if ($ip -and $ip -match ":") {
                $Script:ExternalIPv6 = $ip.Trim()
                Write-Color "Found External IPv6: $Script:ExternalIPv6" -Color DarkGray
                break
            }
        }
    }
}

function Add-Result {
    param($Group, $Service, $v4Result, $v6Result)
    
    if ($v4Result -is [string]) { $v4Result = $v4Result.Trim() }
    if ($v6Result -is [string]) { $v6Result = $v6Result.Trim() }

    $Obj = [PSCustomObject]@{
        Group = $Group
        Service = $Service
        IPv4 = if ($v4Result) { $v4Result } else { "N/A" }
        IPv6 = if ($v6Result) { $v6Result } else { "N/A" }
    }
    $Script:Results += $Obj
    
    if (-not $JsonOutput) {
        $v4Str = if ($v4Result) { $v4Result } else { "N/A" }
        $v6Str = if ($v6Result) { $v6Result } else { "N/A" }
        
        Write-Host "$Service" -ForegroundColor Green -NoNewline
        Write-Host " | " -NoNewline
        
        if ($Script:ExternalIPv4) {
            $Col = if ($v4Str -eq "N/A") {"Gray"} else {"White"}
            Write-Host "v4: $v4Str" -ForegroundColor $Col -NoNewline
            Write-Host " " -NoNewline
        }
        
        if ($Script:ExternalIPv6) {
            $Col = if ($v6Str -eq "N/A") {"Gray"} else {"White"}
            Write-Host "v6: $v6Str" -ForegroundColor $Col -NoNewline
        }
        Write-Host ""
    }
}

function Get-ASN {
    if ($Script:ExternalIPv4) {
        $Json = Invoke-CurlWrapper -Url "https://ipinfo.io/json" -IpVersion 4
        if ($Json -and $Json.org) {
            Write-Color "ISP/ASN: $($Json.org)" -Color Yellow
        }
    }
}

# --- Runners ---

function Run-Primary {
    Write-Color "`n--- Primary GeoIP Services ---" -Color Cyan
    $Services = @(
        @{Name="MAXMIND"; Url="https://geoip.maxmind.com/geoip/v2.1/city/me"; Ref="https://www.maxmind.com"; Path="country.iso_code"}
        @{Name="RIPE"; Url="https://rdap.db.ripe.net/ip/{ip}"; Path="country"}
        @{Name="IPINFO.IO"; Url="https://ipinfo.io/widget/demo/{ip}"; Path="data.country"}
        @{Name="IP-API.COM"; Url="http://ip-api.com/json/{ip}?fields=countryCode"; Path="countryCode"}
        @{Name="CLOUDFLARE"; Url="https://speed.cloudflare.com/meta"; Path="country"}
        @{Name="IPWHO.IS"; Url="https://ipwho.is/{ip}"; Path="country_code"}
    )
    foreach ($Svc in $Services) {
        $v4Res = $null; $v6Res = $null
        if ($Script:ExternalIPv4) {
            $Url = $Svc.Url.Replace("{ip}", $Script:ExternalIPv4)
            $H = @{}; if ($Svc.Ref) { $H["Referer"] = $Svc.Ref }
            if ($Svc.Name -eq "IP-API.COM") { $H["Origin"] = "https://ip-api.com" }
            
            $R = Invoke-CurlWrapper -Url $Url -IpVersion 4 -Headers $H
            if ($R -and $R -isnot [string]) { 
                $Temp = $R; foreach ($P in $Svc.Path.Split('.')) { if ($Temp) { $Temp = $Temp.$P } }; $v4Res = $Temp 
            } elseif ($R -is [string]) { $v4Res = $R }
        }
        if ($Script:ExternalIPv6) {
            $Url = $Svc.Url.Replace("{ip}", $Script:ExternalIPv6)
            $H = @{}; if ($Svc.Ref) { $H["Referer"] = $Svc.Ref }
            $R = Invoke-CurlWrapper -Url $Url -IpVersion 6 -Headers $H
            if ($R -and $R -isnot [string]) { 
                $Temp = $R; foreach ($P in $Svc.Path.Split('.')) { if ($Temp) { $Temp = $Temp.$P } }; $v6Res = $Temp 
            } elseif ($R -is [string]) { $v6Res = $R }
        }
        Add-Result "primary" $Svc.Name $v4Res $v6Res
    }
}

function Run-Custom {
    Write-Color "`n--- Popular Services ---" -Color Cyan
    
    $HandlerGoogle = { param($Ver); $R = Invoke-CurlWrapper -Url "https://www.google.com" -IpVersion $Ver; if ($R -match '"MgUcDb":"([^\"]*)') { return $matches[1] } }
    
    $HandlerYoutube = { param($Ver); $R = Invoke-CurlWrapper -Url "https://www.youtube.com/sw.js_data" -IpVersion $Ver; if ($R -match '\["([A-Z]{2})",') { return $matches[1] } }
    
    $HandlerNetflix = { param($Ver); $R = Invoke-CurlWrapper -Url "https://api.fast.com/netflix/speedtest/v2?https=true&token=$($Script:NetflixApiKey)&urlCount=1" -IpVersion $Ver; if ($R -and $R.client) { return $R.client.location.country } }
    
    # OpenAI (ChatGPT)
    $HandlerOpenAI = {
        param($Ver)
        $Body = '{}'
        $R = Invoke-CurlWrapper -Url "https://ab.chatgpt.com/v1/initialize" -Method POST -Headers @{"Statsig-Api-Key"=$Script:OpenAiStatsigKey} -Body $Body -IpVersion $Ver
        if ($R -and $R.derived_fields) { return $R.derived_fields.country }
        $R2 = Invoke-CurlWrapper -Url "https://chatgpt.com/cdn-cgi/trace" -IpVersion $Ver
        if ($R2 -match "loc=([A-Z]{2})") { return $matches[1] }
    }

    # TikTok
    $HandlerTikTok = {
        param($Ver)
        $R = Invoke-CurlWrapper -Url "https://www.tiktok.com/api/v1/web-cookie-privacy/config?appId=1988" -IpVersion $Ver
        if ($R -and $R.body -and $R.body.appProps) { return $R.body.appProps.region }
    }

    # Steam (Headers)
    $HandlerSteam = {
        param($Ver)
        $R = Invoke-CurlWrapper -Url "https://store.steampowered.com" -Method HEAD -IpVersion $Ver -ReturnHeaders
        if ($R -match "steamCountry=([A-Z]{2})") { return $matches[1] }
    }

    # PlayStation (Headers)
    $HandlerPlayStation = {
        param($Ver)
        $R = Invoke-CurlWrapper -Url "https://www.playstation.com" -Method HEAD -IpVersion $Ver -ReturnHeaders
        if ($R -match "country=([A-Za-z]{2})") { return $matches[1].ToUpper() }
    }

    # JetBrains
    $HandlerJetBrains = {
        param($Ver)
        $R = Invoke-CurlWrapper -Url "https://data.services.jetbrains.com/geo" -IpVersion $Ver
        if ($R -and $R.code) { return $R.code }
    }

    $HandlerReddit = {
        param($Ver)
        $UA = "Reddit/Version 2025.29.0/Build 2529021/Android 13"
        $T = Invoke-CurlWrapper -Url "https://www.reddit.com/auth/v2/oauth/access-token/loid" -Method POST -Headers @{"Authorization"="Basic $Script:RedditBasicToken"; "User-Agent"=$UA} -Body '{"scopes":["email"]}' -IpVersion $Ver
        if ($T -and $T.access_token) {
            $Loc = Invoke-CurlWrapper -Url "https://gql-fed.reddit.com" -Method POST -Headers @{"Authorization"="Bearer $($T.access_token)"; "User-Agent"=$UA} -Body '{"operationName":"UserLocation","variables":{},"extensions":{"persistedQuery":{"version":1,"sha256Hash":"f07de258c54537e24d7856080f662c1b1268210251e5789c8c08f20d76cc8ab2"}}}' -IpVersion $Ver
            if ($Loc -and $Loc.data -and $Loc.data.userLocation) { return $Loc.data.userLocation.countryCode }
        }
        return $null
    }

    $List = @(
        @{Name="Google"; H=$HandlerGoogle}
        @{Name="YouTube"; H=$HandlerYoutube}
        @{Name="OpenAI (ChatGPT)"; H=$HandlerOpenAI}
        @{Name="Netflix"; H=$HandlerNetflix}
        @{Name="TikTok"; H=$HandlerTikTok}
        @{Name="Steam"; H=$HandlerSteam}
        @{Name="PlayStation"; H=$HandlerPlayStation}
        @{Name="JetBrains"; H=$HandlerJetBrains}
        @{Name="Reddit"; H=$HandlerReddit}
    )
    foreach ($Item in $List) {
        $v4=$null; $v6=$null
        if ($Script:ExternalIPv4) { $v4 = & $Item.H -Ver 4 }
        if ($Script:ExternalIPv6) { $v6 = & $Item.H -Ver 6 }
        Add-Result "custom" $Item.Name $v4 $v6
    }
}

function Run-CDN {
    Write-Color "`n--- CDN Services ---" -Color Cyan
    $HandlerCF = { param($Ver); $R = Invoke-CurlWrapper -Url "https://speed.cloudflare.com/meta" -IpVersion $Ver; if ($R) { return "$($R.colo) ($($R.country))" } }
    $HandlerMS = { param($Ver); $R = Invoke-CurlWrapper -Url "https://login.live.com" -IpVersion $Ver; if ($R -match '"sRequestCountry":"([^\"]*)') { return $matches[1] } }
    
    $List = @(@{Name="Cloudflare CDN"; H=$HandlerCF}, @{Name="Microsoft"; H=$HandlerMS})
    foreach ($Item in $List) {
        $v4=$null; $v6=$null
        if ($Script:ExternalIPv4) { $v4 = & $Item.H -Ver 4 }
        if ($Script:ExternalIPv6) { $v6 = & $Item.H -Ver 6 }
        Add-Result "cdn" $Item.Name $v4 $v6
    }
}

# --- Main ---
try {
    if (-not $JsonOutput) { Write-Color "IPRegion (Extended)" -Color Cyan; Write-Color "======================" -Color Gray }
    
    Get-ExternalIP
    
    if (-not $Script:ExternalIPv4 -and -not $Script:ExternalIPv6) {
        Write-Color "Warning: Failed to determine external IP." -Color Yellow
        Write-Color "Proceeding with service checks anyway..." -Color DarkGray
        $Script:ExternalIPv4 = "Unknown"
    } else {
        if (-not $JsonOutput) { Get-ASN }
    }

    if ($Groups -match "all|primary") { Run-Primary }
    if ($Groups -match "all|custom") { Run-Custom }
    if ($Groups -match "all|cdn") { Run-CDN }
        
    if ($JsonOutput) {
        @{ipv4=$Script:ExternalIPv4; ipv6=$Script:ExternalIPv6; results=$Script:Results} | ConvertTo-Json -Depth 5
    }

} catch { Write-Error $_ }