#!/bin/bash

echo "=== Database Diagnosis ==="

# Check if PostgreSQL container is running
echo "1. Checking PostgreSQL container status:"
docker ps | grep postgres

echo -e "\n2. Checking PostgreSQL container logs:"
docker logs koutu-postgres --tail 20

echo -e "\n3. Testing PostgreSQL connection:"
docker exec koutu-postgres pg_isready -U postgres

echo -e "\n4. Checking if test database exists:"
docker exec koutu-postgres psql -U postgres -lqt | cut -d \| -f 1 | grep -qw koutu_test && echo "koutu_test database exists" || echo "koutu_test database NOT found"

echo -e "\n5. Checking database ports:"
netstat -tlnp | grep 5432 || ss -tlnp | grep 5432

echo -e "\n6. Testing connection from host:"
psql "postgresql://postgres:password@localhost:5432/postgres" -c "SELECT version();" 2>&1 | head -3

echo -e "\n=== Diagnosis Complete ==="