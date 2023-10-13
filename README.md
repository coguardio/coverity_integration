# Coverity CoGuard Integration

This repository contains scripts and instructions on how to translate
a result from CoGuard into the format Coverity's third party
integration toolkit ([documentation
here](https://sig-product-docs.synopsys.com/bundle/coverity-docs/page/coverity-analysis/topics/running_the_third_party_integration_toolkit.html))

# How to run it (currently)

- The result folder has usually a `cluster_snapshot.zip` file. Extract it.
- Go into the `/src` directory of this project
- `python -m coguard_coverity_translator <PATH_TO_RESULT_FOLDER>`
- This should generate a `result_coverity.json` file inside that folder.
- Run `./bin/cov-import-results --dir <A_TEMP_FOLDER> <PATH_TO_RESULT_FOLDER>/result_coverity.json`
- Run `./bin/cov-commit-defects --dir <A_TEMP_FOLDER> --host localhost --user admin --port 8090 --stream test_stream` (same temp folder as in the previous step.
