$TTL 300
@   IN  SOA ns.example.com. admin.example.com. (
        1          ; serial
        3600       ; refresh
        900        ; retry
        604800     ; expire
        300 )      ; minimum
    IN  NS  ns.example.com.
