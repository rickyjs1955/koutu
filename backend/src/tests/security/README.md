# Security Tests

## Overview

This directory contains security tests for the backend services, focusing on validating security controls, authorization, input validation, and protection against common vulnerabilities.

## Test Files

- `polygonService.p2.security.test.ts` - Security tests for the polygon service

## Running Security Tests

```bash
npm test -- src/tests/security/
```

## Known Issues

### polygonService.p2.security.test.ts

Two tests are currently skipped due to mock setup issues:
1. "should validate AI suggestion output"
2. "should handle AI processing timeouts"

These tests fail because the `polygonService.suggestPolygons` method attempts to access the image file through the storage service, but there appears to be a mismatch between how the mock is set up and how the service accesses the file.

To fix these tests in the future:
1. Ensure the image file path in the database matches the path where the file is stored in the mock
2. Consider refactoring the suggestPolygons method to handle missing files more gracefully
3. Add proper timeout handling to the service if timeout tests are needed

## Test Categories

### Authorization Attacks
- Tests for IDOR (Insecure Direct Object Reference) vulnerabilities
- Cross-user access prevention
- Permission validation for all operations

### Input Validation
- SQL injection prevention
- XSS (Cross-Site Scripting) protection
- Invalid data handling
- Boundary value testing

### Business Logic
- Enforcement of business rules
- State transition validation
- Race condition handling

### Resource Exhaustion
- Protection against DoS attacks
- Memory usage limits
- Processing limits

### File System Security
- Path traversal prevention
- Safe file handling
- Error recovery

### AI Feature Security
- Authorization for AI features
- Input/output validation
- Timeout handling

### Data Integrity
- Referential integrity
- Orphaned data handling
- Transaction consistency

### Audit and Logging
- Sensitive data protection in logs
- Security event logging
- Error message sanitization

## Database Schema Requirements

The security tests expect the following database schema:
- `users` table with columns: id, email, password_hash, created_at, updated_at
- `original_images` table with columns: id, user_id, original_filename, file_path, status, original_metadata, upload_date, created_at, updated_at
- `polygons` table with columns: id, user_id, original_image_id, points, label, metadata, created_at, updated_at

## Mock Setup

The tests use extensive mocking for:
- Storage service (file operations)
- Polygon processor (AI operations)
- PolygonServiceUtils (calculations and ML data saving)

Make sure all mocks are properly restored between tests to avoid interference.