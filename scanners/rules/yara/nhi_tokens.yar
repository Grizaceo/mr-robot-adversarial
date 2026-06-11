rule nhi_github_pat {
    meta:
        description = "Detect GitHub Personal Access Tokens (PAT) in files"
        author = "Elliot NHI Governance"
        date = "2026-06-07"
        mitre_technique = "T1528, T1078.004"
        severity = "critical"
    strings:
        $pat_v1 = /ghp_[A-Za-z0-9_]{36,}/
        $pat_v2 = /github_pat_[A-Za-z0-9_]{36,}/
        $oauth = /gho_[A-Za-z0-9_]{36,}/
        $user_to_server = /ghu_[A-Za-z0-9_]{36,}/
        $app_token = /ghs_[A-Za-z0-9_]{36,}/
        $refresh = /ghr_[A-Za-z0-9_]{36,}/
    condition:
        any of them
}

rule nhi_gitlab_token {
    meta:
        description = "Detect GitLab Personal Access Tokens in files"
        author = "Elliot NHI Governance"
        date = "2026-06-07"
        mitre_technique = "T1528"
        severity = "high"
    strings:
        $glpat = /glpat-[A-Za-z0-9\-_]{20,}/
    condition:
        $glpat
}

rule nhi_aws_key {
    meta:
        description = "Detect AWS Access Key IDs in files"
        author = "Elliot NHI Governance"
        date = "2026-06-07"
        mitre_technique = "T1528"
        severity = "critical"
    strings:
        $akid = /(AKIA|ASIA)[A-Z0-9]{16}/
    condition:
        $akid
}

rule nhi_token_exfil {
    meta:
        description = "Detect token exfiltration patterns in CI artifacts"
        author = "Elliot NHI Governance"
        date = "2026-06-07"
        mitre_technique = "T1041, T1528"
        severity = "critical"
    strings:
        $exfil_curl = "curl -X POST" nocase
        $exfil_wget = "wget --post-data" nocase
        $token_ref = /(TOKEN|SECRET|PASSWORD|API_KEY|PAT)\s*=\s*["'][A-Za-z0-9_\-\.]{16,}["']/
        $artifact_upload = /upload.*(artifact|build|dist|coverage)/
    condition:
        ($token_ref or $exfil_curl or $exfil_wget) and $artifact_upload
}
