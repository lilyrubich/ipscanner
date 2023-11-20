# IPScanner
Scanning ip addresses for retrieving domain names. Checking IPs occurs in several threads (number of threads is chosen by the user). The more threads the faster the program runs.

The Application is getting input arguments:
  * IP with mask value (example: 8.8.8.8/32)
  * Number of threads

and returning .txt file with domain names that were found from SSL certificates for input IP addresses.
