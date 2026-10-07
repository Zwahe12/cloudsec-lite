RULES = [
    {
        "id": "AWS-S3-001",
        "title": "S3 bucket allows public-read ACL",
        "severity": "CRITICAL",
        "pattern": r'acl\s*=\s*"public-read(?:-write)?"',
        "recommendation": "Use private ACLs and enable S3 Block Public Access.",
    },
    {
        "id": "AWS-SG-001",
        "title": "Security group exposes SSH to the internet",
        "severity": "HIGH",
        "pattern": r'from_port\s*=\s*22.*?to_port\s*=\s*22.*?cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0/0"[^\]]*\]',
        "recommendation": "Restrict port 22 to trusted admin IP ranges or use a managed access service.",
    },
    {
        "id": "AWS-SG-002",
        "title": "Security group exposes RDP to the internet",
        "severity": "HIGH",
        "pattern": r'from_port\s*=\s*3389.*?to_port\s*=\s*3389.*?cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0/0"[^\]]*\]',
        "recommendation": "Restrict port 3389 to trusted IP ranges or use a secure bastion/access gateway.",
    },
    {
        "id": "AWS-IAM-001",
        "title": "IAM policy grants wildcard actions",
        "severity": "CRITICAL",
        "pattern": r'"Action"\s*:\s*(?:"\*"|\[\s*"\*"\s*\])',
        "recommendation": "Apply least privilege and explicitly list only required IAM actions.",
    },
    {
        "id": "AWS-RDS-001",
        "title": "RDS instance is publicly accessible",
        "severity": "HIGH",
        "pattern": r'publicly_accessible\s*=\s*true',
        "recommendation": "Set publicly_accessible = false and place the database in private subnets.",
    },
    {
        "id": "AWS-EBS-001",
        "title": "EBS encryption explicitly disabled",
        "severity": "MEDIUM",
        "pattern": r'encrypted\s*=\s*false',
        "recommendation": "Enable encryption for EBS volumes and snapshots.",
    },
]
