# FIPS-Enabled Elastic Stack Environment

This project provides a Docker-based development environment for testing Logstash in FIPS mode with Elasticsearch and Filebeat. The setup includes SSL/TLS encryption and proper certificate generation.


## Setup 

Check out this fork/branch
```bash
# Docker setup controlled from docker dir
cd qa/fips/docker
# Generate certs (only need to run this once)
chmod +x generate-certs.sh
./generate-certs.sh
# start docker-compose stack
docker compose up
```

## Testing Data Flow

1. Create a test log entry:
```bash
echo "Test log entry $(date)" >> filebeat-logs/test.log
```

2. Verify data is flowing through the stack:

Check indices in Elasticsearch:
```bash
curl -k -u elastic:changeit https://localhost:9200/_cat/indices?v
```

Search for documents:
```bash
curl -k -u elastic:changeit 'https://localhost:9200/logstash-fips-test-*/_search?pretty' -H 'Content-Type: application/json' -d '
{
  "sort": [
    {
      "@timestamp": {
        "order": "desc"
      }
    }
  ]
}'
```

## Clean Up

To stop the environment and remove all data:
```bash
docker compose down -v
```

To manually delete indices:
```bash
curl -k -u elastic:changeit -X DELETE 'https://localhost:9200/logstash-fips-test-*'
```

## Directory Structure

```
➜  fips git:(shareable-fips-env) ✗ tree
.
├── config
│   └── security
│       ├── java.policy
│       └── java.security
└── docker
    ├── Dockerfile
    ├── certs
    │   ├── ca.crt
    │   ├── ca.key
    │   ├── es01.crt
    │   └── es01.key
    ├── docker-compose.yml
    ├── filebeat-logs
    │   └── test.log
    ├── filebeat.yml
    ├── generate-certs.sh
    └── pipelines
        └── fips-test-pipeline.conf

7 directories, 12 files
```

