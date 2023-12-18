# Coverity CoGuard Integration

This repository contains scripts and instructions on how to translate
a result from CoGuard into the format Coverity's third party
integration toolkit ([documentation
here](https://sig-product-docs.synopsys.com/bundle/coverity-docs/page/coverity-analysis/topics/running_the_third_party_integration_toolkit.html))

# How to install the integration

The integration is installed as part of the [CoGuard
CLI](https://github.com/coguardio/coguard-cli). Please follow the
installation instructions there.

# How to run it inside your CI/CD pipeline

Example scripts are provided inside this repository, found
[here](./example_scripts). You can copy the scripts and
alter it for your respective use-case.

# Roadmap items

## Supporting Windows

In the
[documentation](https://sig-product-docs.synopsys.com/bundle/coverity-docs/page/coverity-analysis/topics/import_file_format_and_reference.html#cim_TPIP_import_format_examples__cim_TPIT_json),
the translated JSON requires to use forward-slashes independent from the environment
where the script is running. Right now, we are using the operating
system path separator. [See the open issue for more
details](https://github.com/coguardio/coverity_integration/issues/1).

## File-independent flags

The third party integration toolkit requires currently a flag to be
associated to a file. Some of our checks are independent from a specific file,
or are even just there because the file does not exist. Right now, we
filter those checks out.

Once defects that are not tied to a file are supported in Coverity, we
will add these checks into the list.
