# ============================================================
#  VettaiyanEDR -- Elasticsearch Index Template Setup
# ============================================================
#  Run this ONCE after docker compose up:
#    cd elk
#    .\setup-index.ps1
#
#  Creates:
#    - Index template with proper field mappings
#    - ILM policy for automatic rollover (7 days retention)
#    - Kibana data view for the dashboard
# ============================================================

$esHost = "http://localhost:9200"
$kibanaHost = "http://localhost:5601"
$indexPattern = "vettaiyan-events"

Write-Host ""
Write-Host "  ========================================================"
Write-Host "  VettaiyanEDR -- Elasticsearch Setup"
Write-Host "  ========================================================"
Write-Host ""

# --- Wait for Elasticsearch ---
Write-Host "  [*] Waiting for Elasticsearch at $esHost ..."
$retries = 30
for ($i = 0; $i -lt $retries; $i++) {
    try {
        $null = Invoke-RestMethod -Uri "$esHost/_cluster/health" -TimeoutSec 2 -ErrorAction Stop
        Write-Host "  [OK] Elasticsearch is ready"
        break
    } catch {
        if ($i -eq $retries - 1) {
            Write-Host "  [FAIL] Elasticsearch not reachable after $retries attempts"
            exit 1
        }
        Start-Sleep -Seconds 2
    }
}

# --- ILM Policy (auto-delete after 7 days) ---
Write-Host "  [*] Creating ILM policy..."
$ilmPolicy = @{
    policy = @{
        phases = @{
            hot = @{
                min_age = "0ms"
                actions = @{}
            }
            delete = @{
                min_age = "7d"
                actions = @{
                    delete = @{}
                }
            }
        }
    }
} | ConvertTo-Json -Depth 5

try {
    Invoke-RestMethod -Uri "$esHost/_ilm/policy/vettaiyan-ilm" -Method Put -Body $ilmPolicy -ContentType "application/json" | Out-Null
    Write-Host "  [OK] ILM policy created (7-day retention)"
} catch {
    Write-Host "  [WARN] ILM policy: $($_.Exception.Message)"
}

# --- Index Template ---
Write-Host "  [*] Creating index template..."
$template = @{
    index_patterns = @("$indexPattern*")
    template = @{
        settings = @{
            number_of_shards = 1
            number_of_replicas = 0
            "index.lifecycle.name" = "vettaiyan-ilm"
        }
        mappings = @{
            properties = @{
                host = @{ type = "keyword" }
                eventType = @{ type = "keyword" }
                processId = @{ type = "integer" }
                threadId = @{ type = "integer" }
                sequenceNumber = @{ type = "long" }
                timestamp = @{
                    type = "date"
                    format = "strict_date_optional_time||epoch_millis"
                }
                detail = @{
                    type = "text"
                    fields = @{
                        keyword = @{
                            type = "keyword"
                            ignore_above = 2048
                        }
                    }
                }
            }
        }
    }
    priority = 100
} | ConvertTo-Json -Depth 10

try {
    Invoke-RestMethod -Uri "$esHost/_index_template/vettaiyan-events-template" -Method Put -Body $template -ContentType "application/json" | Out-Null
    Write-Host "  [OK] Index template created"
} catch {
    Write-Host "  [FAIL] Index template: $($_.Exception.Message)"
}

# --- Create the index explicitly ---
Write-Host "  [*] Creating index..."
try {
    Invoke-RestMethod -Uri "$esHost/$indexPattern" -Method Put -ContentType "application/json" -Body "{}" | Out-Null
    Write-Host "  [OK] Index '$indexPattern' created"
} catch {
    $err = $_.Exception.Message
    if ($err -match "already_exists") {
        Write-Host "  [OK] Index '$indexPattern' already exists"
    } else {
        Write-Host "  [WARN] Index creation: $err"
    }
}

# --- Wait for Kibana ---
Write-Host "  [*] Waiting for Kibana at $kibanaHost ..."
for ($i = 0; $i -lt $retries; $i++) {
    try {
        $resp = Invoke-RestMethod -Uri "$kibanaHost/api/status" -TimeoutSec 2 -ErrorAction Stop
        if ($resp.status.overall.level -eq "available") {
            Write-Host "  [OK] Kibana is ready"
            break
        }
    } catch {}
    if ($i -eq $retries - 1) {
        Write-Host "  [WARN] Kibana not ready -- create data view manually"
        break
    }
    Start-Sleep -Seconds 3
}

# --- Kibana Data View ---
Write-Host "  [*] Creating Kibana data view..."
$dataView = @{
    data_view = @{
        title = "$indexPattern*"
        name = "VettaiyanEDR Events"
        timeFieldName = "timestamp"
    }
} | ConvertTo-Json -Depth 5

try {
    $headers = @{ "kbn-xsrf" = "true" }
    Invoke-RestMethod -Uri "$kibanaHost/api/data_views/data_view" -Method Post -Body $dataView -ContentType "application/json" -Headers $headers | Out-Null
    Write-Host "  [OK] Kibana data view created"
} catch {
    $err = $_.Exception.Message
    if ($err -match "Duplicate") {
        Write-Host "  [OK] Kibana data view already exists"
    } else {
        Write-Host "  [WARN] Kibana data view: $err"
    }
}

# --- Done ---
Write-Host ""
Write-Host "  ========================================================"
Write-Host "  Setup complete!"
Write-Host ""
Write-Host "  Elasticsearch : $esHost"
Write-Host "  Kibana         : $kibanaHost"
Write-Host "  Index          : $indexPattern"
Write-Host "  Retention      : 7 days (ILM auto-delete)"
Write-Host ""
Write-Host "  Next steps:"
Write-Host "    1. Edit vettaiyan.ini on the agent machine:"
Write-Host "       [Shipper]"
Write-Host "       Endpoint=http://<this-machine-ip>:9200/_bulk"
Write-Host "       IndexOrToken=$indexPattern"
Write-Host ""
Write-Host "    2. Restart the Vettaiyan agent service"
Write-Host "    3. Open Kibana: $kibanaHost"
Write-Host "       Go to Discover > select 'VettaiyanEDR Events'"
Write-Host "  ========================================================"
Write-Host ""
