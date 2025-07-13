# GraphQLCLI - Enhanced Features Documentation

## Overview

GraphQLCLI has been significantly enhanced with multiple engines, advanced security testing, and comprehensive fingerprinting capabilities. This module now supports 4 main engines and multiple security assessment features.

## Supported Engines

### 1. GraphW00F (Default)
- **Purpose**: Advanced GraphQL fingerprinting and engine detection
- **Features**: 
  - Detects 30+ GraphQL implementations
  - Engine version detection
  - Technology stack fingerprinting
  - Error pattern analysis

### 2. GraphQL-Cop
- **Purpose**: Security vulnerability scanning
- **Features**:
  - Introspection detection
  - Common vulnerability checks
  - Security configuration analysis

### 3. GraphQLMap
- **Purpose**: Interactive GraphQL testing and exploitation
- **Features**:
  - Schema dumping via introspection
  - SQL/NoSQL injection testing
  - Batching support testing
  - Field fuzzing capabilities

### 4. GQL (Python Client)
- **Purpose**: Python-based GraphQL client for detailed analysis
- **Features**:
  - Comprehensive introspection
  - Schema analysis
  - Type and directive enumeration

## New Security Features

### Threat Matrix Assessment (`--threat-matrix`)
Implements GraphQL-specific security tests based on the GraphQL Threat Matrix:

1. **Introspection Vulnerability**
   - Tests if introspection is enabled in production
   - Severity: Medium

2. **Deep Recursion DoS**
   - Tests for query depth limit vulnerabilities
   - Severity: High

3. **Field Duplication DoS**
   - Tests for field duplication attacks
   - Severity: Medium

4. **Alias Overload DoS**
   - Tests for alias-based resource exhaustion
   - Severity: Medium

5. **Directive Overload DoS**
   - Tests for directive-based attacks
   - Severity: Low

### GraphQL Fingerprinting (`--fingerprint`)
Advanced engine detection using:
- Error message patterns
- Response headers analysis
- Query behavior differences
- Implementation-specific features

### Batch Query Testing (`--batch-queries`)
Tests GraphQL batching support with various batch sizes:
- Small batches (2-5 queries)
- Medium batches (10-50 queries)
- Large batches (100+ queries)
- Performance impact analysis

### Injection Testing
- **SQL Injection** (`--sqli-test`): Tests for SQL injection vulnerabilities
- **NoSQL Injection** (`--nosqli-test`): Tests for NoSQL injection vulnerabilities

## Usage Examples

### Basic Usage
```bash
# Basic scan with GraphW00F
python graphqlcli.py --domain target.com

# Use all engines
python graphqlcli.py --domain target.com --engine all

# Custom endpoint
python graphqlcli.py --domain target.com --endpoint /api/v2/graphql
```

### Advanced Security Testing
```bash
# Full security assessment
python graphqlcli.py --domain target.com \
  --engine all \
  --threat-matrix \
  --fingerprint \
  --detect-engines \
  --batch-queries \
  --sqli-test \
  --nosqli-test \
  --report \
  --verbose

# Specific vulnerability tests
python graphqlcli.py --domain target.com \
  --threat-matrix \
  --depth-limit \
  --rate-limit
```

### Output Options
```bash
# Generate comprehensive report
python graphqlcli.py --domain target.com \
  --engine all \
  --json-output \
  --csv-output \
  --report

# Store session for later analysis
python graphqlcli.py --domain target.com \
  --store-db \
  --output-dir /path/to/results
```

### Session Management
```bash
# Resume previous session
python graphqlcli.py --domain target.com --resume

# Check session status
python graphqlcli.py --domain target.com --resume-stat

# Reset session
python graphqlcli.py --domain target.com --resume-reset
```

## Output Formats

### JSON Output
Structured data containing:
- Engine results
- Vulnerability assessments
- Fingerprinting data
- Performance metrics

### CSV Output
Tabular format for:
- Vulnerability summary
- Test results
- Engine comparisons

### Markdown Reports
Comprehensive security reports including:
- Executive summary
- Detailed findings
- Risk assessment
- Recommendations
- Tool descriptions

## Security Recommendations

### High Priority
1. **Disable Introspection** in production environments
2. **Implement Query Depth Limiting** (recommended: 10-15 levels)
3. **Use Query Complexity Analysis** for resource management

### Medium Priority
1. **Enable Rate Limiting** on GraphQL endpoints
2. **Implement Query Whitelisting** for critical applications
3. **Use Query Timeouts** to prevent long-running queries

### Low Priority
1. **Enable Query Logging** for security monitoring
2. **Implement Query Cost Analysis**
3. **Use Schema Validation** for input sanitization

## Dependencies

Required Python packages:
```bash
pip install requests gql[all] click
```

Optional tools for enhanced functionality:
```bash
# GraphW00F
pip install graphw00f

# GraphQL-Cop
go install github.com/dolevf/graphql-cop@latest

# GraphQLMap
git clone https://github.com/swisskyrepo/GraphQLmap
cd GraphQLmap && pip install -r requirements.txt
```

## Integration with ReconCLI

GraphQLCLI integrates seamlessly with the ReconCLI ecosystem:

1. **Database Integration**: Results can be stored in ReconCLI database
2. **Report Generation**: Markdown reports compatible with other modules
3. **Session Management**: Consistent with other ReconCLI tools
4. **Output Formats**: Standard JSON/CSV formats for analysis

## Performance Considerations

- **Timeout Settings**: Default 30 seconds, adjustable via `--timeout`
- **Threading**: Configurable via `--threads` (default: 10)
- **Memory Usage**: Large schemas may require additional memory
- **Network Impact**: Batch testing can generate significant traffic

## Error Handling

The tool includes comprehensive error handling for:
- Network connectivity issues
- Tool availability checks
- Invalid GraphQL endpoints
- Timeout scenarios
- Permission errors

## Troubleshooting

### Common Issues

1. **Dependencies Not Found**
   ```bash
   pip install requests gql[all] click
   ```

2. **External Tools Missing**
   - Install GraphW00F, GraphQL-Cop, or GraphQLMap separately
   - Tool will fallback to manual implementation

3. **Permission Errors**
   - Check file system permissions
   - Ensure output directory is writable

4. **Network Issues**
   - Verify target accessibility
   - Check proxy settings
   - Adjust timeout values

## Future Enhancements

Planned features:
- GraphQL subscription testing
- Custom payload injection
- Advanced DoS testing
- Integration with Burp Suite
- Custom rule engine
- Multi-threaded scanning
- WebSocket support
