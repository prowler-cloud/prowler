# Azure subscriptions scope

By default, Prowler is multisubscription, which means that is going to scan all the subscriptions is able to list. If you only assign permissions to one subscription, it is going to scan a single one.
Prowler also has the ability to limit the subscriptions to scan to a set passed as input argument, to do so:

```console
prowler azure --az-cli-auth --subscription-ids <subscription ID 1> <subscription ID 2> ... <subscription ID N>
```

Where you can pass from 1 up to N subscriptions to be scanned.
