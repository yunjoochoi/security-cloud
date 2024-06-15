# Security_Cloud
Highly-scalable searchable symmetric encryption with support for Boolean queries (2013) Implementation of SSE system using Tset protocol in the paper


## the packet design
![packet design](https://raw.githubusercontent.com/sfsfsefs/images/4689220e36703e75b12338b1b19db14089bc5576/1.png)


## Networking
![Networking](https://raw.githubusercontent.com/sfsfsefs/images/4689220e36703e75b12338b1b19db14089bc5576/2.png)


## DB


The file table contains encrypted files and their owners.
File search is provided only within the user's own set of files using a foreign key.

![file_table](https://raw.githubusercontent.com/sfsfsefs/images/4689220e36703e75b12338b1b19db14089bc5576/3.png)


The client table contains a Tset, which the scheme uses to enable secure search.

![file_table](https://raw.githubusercontent.com/sfsfsefs/images/4689220e36703e75b12338b1b19db14089bc5576/4.png)
