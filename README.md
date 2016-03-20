# matrix-federation-inspector

A diagnostic tool for Matrix federation.

```
USAGE:
    mxfedtest [FLAGS] [OPTIONS] [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -n, --nameserver <IP>    Sets the nameserver to use

SUBCOMMANDS:
    fetch      Fetches information about a server
    help       Prints this message or the help message of the given subcommand(s)
    report     Generates a full report about a server
    resolve    Resolves server name to IP/port

```

# Examples

```
$ mxfedtest report matrix.org
SRV Records...
+-------------------------+----------+--------+------+------------+
| Query                   | Priority | Weight | Port | Target     |
+=========================+==========+========+======+============+
| _matrix._tcp.matrix.org | 10       | 5      | 8448 | matrix.org |
+-------------------------+----------+--------+------+------------+

Hosts...
+------------+--------------+
| Host       | Target       |
+============+==============+
| matrix.org | 83.166.64.33 |
+------------+--------------+

Testing TLS connections...

+--------------+------+------------+------------------+-----------------------------+---------+------+
| IP           | Port | Name       | Certificate      | Cipher Name                 | Version | Bits |
+==============+======+============+==================+=============================+=========+======+
| 83.166.64.33 | 8448 | matrix.org | 1691F95BED11787E | ECDHE-RSA-AES256-GCM-SHA384 | TLSv1.2 | 256  |
|              |      |            | 65F300E4F691B4C9 |                             |         |      |
|              |      |            | 9DA112057671CBE2 |                             |         |      |
|              |      |            | 5F6AB887BE28EC94 |                             |         |      |
+--------------+------+------------+------------------+-----------------------------+---------+------+

+--------------------+--------------+
| Fingerprint SHA256 | CN           |
+====================+==============+
| 1691F95BED11787E   | *.matrix.org |
| 65F300E4F691B4C9   |              |
| 9DA112057671CBE2   |              |
| 5F6AB887BE28EC94   |              |
+--------------------+--------------+

 IP/Port           83.166.64.33:8448 
 Server Name       matrix.org 
 Valid until       2016-03-18 21:48:40.973 
 Server Header     Synapse/0.13.3 (b=develop,e462aa9,dirty) 
 Verify key        ed25519:auto Noi6WqcDj0QmPxCNQqgezwTlBKrfqehY1u2FyWP9uYw 
 TLS fingerprint   1691F95BED11787E65F300E4F691B4C99DA112057671CBE25F6AB887BE28EC94 

```


```
$ mxfedtest resolve jki.re
212.71.233.145:8080
[2a01:7e00::f03c:91ff:fe6e:411b]:8080
```
