#!/bin/bash

set -ex

# The cluster you wish to include into the Coverity report.
COGUARD_CLUSTER=$1

# The location where the Coverity analysis scripts are being stored.
# The folder is usually named `cov-analysis-VERSION`.
COVERITY_LOCATION=$2;

# The host where the Coverity platform is running.
COVERITY_HOST=$3;

# The port of the Coverity platform. The default is 443.
COVERITY_PORT=${4:-443};

# The username to use for Coverity. The default is `admin`.
COVERITY_USER=${5:-admin};

# The stream where the results should be stored inside Coverity.
# By default, the cluster name is being used.
COVERITY_STREAM=${6:-$COGUARD_CLUSTER};

# The current location to be used to store all temporary files
TEMP_LOCATION_PREFIX=${7:-$(pwd)};

# Testing that all input parameters are set to a value
test -n "$COGUARD_CLUSTER";
test -n "$COVERITY_LOCATION";
test -n "$COVERITY_HOST";
test -n "$COVERITY_PORT";
test -n "$COVERITY_USER";
test -n "$COVERITY_STREAM";
# This is not an input parameter, but should be available in the environment.
test -n "$COVERITY_PASSWORD";

# Creation of a temporary directory, where the results from
# CoGuard are being stored.
TEMP_DIR=$(mktemp -d --tmpdir="$TEMP_LOCATION_PREFIX");

# Download the latest report from coguard for the chosen cluster and
# store it as ZIP.
coguard account \
        download-cluster-report \
        "$COGUARD_CLUSTER" \
        "$TEMP_DIR"/"$COGUARD_CLUSTER"_DOWNLOAD.zip;

# Unzip the contentes and the snapshot. This will generate a folder-structure
# as following:
# - result.json
# - [result.md]
# + cluster_snapshot
#   - content-files
unzip -u "$TEMP_DIR"/"$COGUARD_CLUSTER"_DOWNLOAD.zip -d "$TEMP_DIR";
unzip -u "$TEMP_DIR"/cluster_snapshot.zip -d "$TEMP_DIR"/cluster_snapshot

# Run the Coverity translator script. This will transform `result.json`
# into the Coverity format and store the new JSON in `result_coverity.json`.
coguard-coverity-translator "$TEMP_DIR";

# Create a folder where `cov-import-results` (script by Coverity) can store
# their intermediate files.
mkdir -p "$TEMP_DIR"/cov-translation

# Run `cov-import-results` with respect to result_coverity.json
"$COVERITY_LOCATION"/bin/cov-import-results \
                    --dir "$TEMP_DIR"/cov-translation \
                    "$TEMP_DIR"/result_coverity.json

# Commit the new set of defects into the Coverity platform.
"$COVERITY_LOCATION"/bin/cov-commit-defects \
                    --dir "$TEMP_DIR"/cov-translation \
                    --host "$COVERITY_HOST" \
                    --user "$COVERITY_USER" \
                    --password "$COVERITY_PASSWORD" \
                    --port "$COVERITY_PORT" \
                    --stream "$COVERITY_STREAM"

# Cleanup
rm -rf "$TEMP_DIR"
