# The_Inspector

# Redirect Tracker

A Python script to dig into a domain’s details—redirects, WHOIS, DNS records, SSL certs, and more. It’s a handy tool for poking around websites to see what’s under the hood, like following redirect chains or checking server headers.

## Features

- Follows Redirects: Tracks HTTP redirects (such as 301 or 302) from a domain to its final destination, displaying the whole chain.
- Grabs WHOIS Info: Retrieves network details (such as NetName and OrgName) for the domain’s IP address.
- Checks DNS Records: Looks up MX, TXT, and CNAME records.
- Analyzes SSL Certs: Extracts issuer, subject, and validity dates for HTTPS sites.
- Scans Headers: Displays key HTTP headers ( Server, Content-Type).
- Detects JavaScript: Spots inline scripts, .js files, or JavaScript URLs on the final page.
- Extracts Links: Grabs up to 10 links from the final page (needs beautifulsoup4).
- Exports Results: Saves output as JSON, CSV, or TXT.

---

#Usage
To use the script, run it with Python and enter the domain you wish to track:
```bash
Enter the domain: example.com
```
Or, run without a domain to get an interactive prompt:

```bash
python theinspector.py
# Enter the domain: example.com
```
----

# Flags

--no-art: Skip the ASCII art banner for a cleaner output.
``` bash

python theinspector.py example.com --no-art
```

--user-agent <string>: Set a custom User-Agent for HTTP requests.
```bash
python theinspector.py example.com --user-agent "MyCustomAgent/1.0"
```

--output-format <json|csv|txt>: Export results to a file in the chosen format.
```bash
python theinspector.py example.com --output-format json
```

--output-file <filename>: Specify a custom output file name (defaults to inspector_domain_timestamp.format).
```bash
python theinspector.py example.com --output-format txt --output-file results.txt
Example Output
For example.com:
Redirect Chain Summary:
 301 -> https://example.com/ -> https://example.tech
 200 -> https://example.tech

Final Destination: https://example.tech
 - IP Address: IP
 - MIME-Type: text/html; charset=UTF-8
 - Status: 200
 - Type: Document
 - Location: N/A
```
# Notes
The script retries failed requests up to 3 times with a 20-second timeout.
Redirects are capped at 10 to avoid infinite loops.
If redirects aren’t followed (like 301 issues), check your network or the domain’s setup.
IP addresses may vary due to load balancers (like Cloudflare).

---
# Fallback

If the new version of the tool doesn't work on your machine, you can use the old version instead.

---
# Version

      v1.1: Basic redirection, DNS, WHOIS (via ipwhois lib), reverse DNS.

      v1.3: Adds:

         - SSL cert parsing

         - DNS record extraction (MX, TXT, CNAME)

         - Header classification

         - JS detection

         - Top-10 link extraction (uses BeautifulSoup, optional dep)

      gv1.1: Adds graphical insights for better visibility and presentation.
      
        - Redirect Graph (Graphviz): Visual map of the entire redirect chain — each URL is a node, edges show HTTP status and Location.
        
        - Edge Labeling: Arrows include metadata, such as redirect status codes and target URLs, which facilitate debugging of chained redirects.
        
        - Node Styling: URLs are displayed as colored boxes, making the flow easier to trace.

      v2.0: builds on everything from v1.3 and gv1.1, and adds:

        -  Graphviz + Matplotlib support for two types of redirect chain visualizations (user can choose)

        -  Interactive CLI menu before scan (user configures output format, file name, user-agent, and ASCII art)

        -  Matplotlib flowchart using networkx – less dependency-heavy and customizable
      

 * Output & Export

   - v1.1: Console logging only.

   - v1.3: Supports export to JSON, CSV, and TXT. Useful for reporting and automation.

   - gv1.1: Adds PNG export of the redirect graph. Keeps the same structured data export as v1.3.
  
   - v2.0: Export Formats: JSON, CSV, TXT (same as v1.3), filename Customization: Manual or auto (timestamped), user-controlled Output: Optional export via CLI or interactive prompt.
      - Logs + Visuals: Combines both for human and machine parsing and reporting.
      - Redirect Graphs:
       * Graphviz → PNG ( redirect_graphviz_<domain>.png)
       *  Matplotlib → Flowchart PNG ( redirect_matplotlib_<domain>.png)
    



