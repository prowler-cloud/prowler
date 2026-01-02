# TODO

- common labels uses selector labels, fix
- create docs
- add the UI component
- add a bunch of configmaps and secrets
- Readiness probes
- good default security context
- automated release flow
- create example how to deploy valkey and postgres but document something better
- fix some autoscale for celery worker?
- add checksum sha for automatic restart if cm updated
- fix chart version to at least be close to the current version
- put the different resources in different files/folders

## Question

Can the API have multiple replicas? The entrypoint triggers a DB migration during startup, how is looking handled in the DB?

Does the celery broker/worker need the mega configmap?
What env vars does it need? Anything else then connect to valkey?

## Set config

Currently using some ugly virtual env path `home/prowler/.cache/pypoetry/virtualenvs/prowler-api-NnJNioq7-py3.12/lib/python3.12/site-packages/`.

Prowler supports CLI [setting](https://github.com/prowler-cloud/prowler/blob/8a144a4046d27d0dfb406638d7220f681cfde73f/prowler/lib/cli/parser.py#L344-L353)
`--config-file`, easeist to hardcode that value to always be a part of the arg. It might create some issues though.

Add this config + some custom env var to define where the config file is located.
Obviusly make to a helm var...

```yaml
          volumeMounts:
            - name: main-config
              mountPath: /tmp/
              subPath: config.yaml
      volumes:
        - name: main-config
          configMap:
            name: {{ include "prowler.fullname" . }}-config
```
