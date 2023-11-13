# The_Inspector

# Redirect Tracker

This script is designed to follow the trail of HTTP(S) redirects when accessing a web domain. It is helpful for debugging, SEO analysis, and tracking the final destination of a URL.

## Features

- Follows up to 10 redirects by default.
- Logs the entire redirect chain along with status codes and IP addresses.
- Warns if a redirect attempts to initiate a file download.
- User-agent string mimicry for improved website compatibility.
- Uses Python's `requests` library for handling HTTP requests.

## Requirements

- Python 3
- `requests` library

To install the required `requests` library, run the following:

```bash
pip install requests

```
#Usage
To use the script, run it with Python and enter the domain you wish to track:
Enter the domain: example.com






