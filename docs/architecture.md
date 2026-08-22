# Architecture

## Control path

Server periodically reports status, connected Client IDs, and local interface addresses to Controller through TLS 1.3. It then pulls the current Client allow-list and effective mappings. A unique Server Token authenticates both requests; Controller stores only its SHA-256 hash.

```text
Server -- TLS + Server Token --> Controller report
Server <-- desired configuration -- Controller
```

## Tunnel path

Client maintains a TLS 1.3 long connection to its bound Server. The first protocol frame carries the Client ID and unique Token. Server compares its hash with the allow-list pulled from Controller. Each public TCP connection and UDP peer flow receives a stream ID and is multiplexed through the encrypted connection. UDP peer flows expire after 60 seconds of inactivity.

```text
Public TCP/UDP user -> Server listener -> OpenStream/OpenDatagram + Data -> Client -> intranet target
```

Heartbeats run every 15 seconds. Server pulls Controller configuration every 10 seconds. Removing a Client deletes its mappings; the following configuration pull closes an existing revoked tunnel and prevents reconnection.

## Bound packages

Each Server ZIP contains one platform executable and a `server.json` sidecar with its Server ID, endpoints, Token, private key, certificate, and CA. Each Client ZIP contains an executable and `client.json` with its Client ID, bound Server endpoint, Token, and CA. Agents locate the sidecar beside their own executable rather than relying on the current working directory. Linux and macOS ZIP metadata uses `0755` for executables and `0600` for the identity JSON.

## Mapping priority

Mappings are grouped by Server, protocol, public IP, and public port. The highest priority item is `effective`; lower priority items are `occupied` and record the winning mapping ID. When the winner is removed, the next item becomes effective automatically. TCP and UDP bindings are resolved independently.

## Encryption and trust

Only TLS server certificates are used. Client certificates and mutual TLS are not required. Controller owns an internal CA and embeds its public certificate in bound packages, while agents also retain system roots so a normal Nginx HTTPS certificate can front the Controller agent endpoint.

Controller renews a Server certificate when its endpoint changes or expiry is within 30 days. The authenticated configuration response carries the renewed certificate, and Server atomically swaps it into the TLS listener while retaining the private key sealed in `server.json`.
