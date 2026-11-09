#!/bin/bash

# Exits script if any command returns an error
set -e

# Builds web app with Docker
echo "Starting Docker containers."
docker compose up -d --build

# Runs all unittests in test file
echo "Running unittests."
docker compose exec web python -m unittest discover -s tests -v

echo "All tests completed successfully!"