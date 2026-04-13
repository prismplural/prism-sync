# Prism Relay — Kubernetes

Deploy the Prism relay server on Kubernetes.

## Quick start

1. Edit `configmap.yaml` with your settings.
2. (Optional) Set a custom `REGISTRATION_TOKEN` in `secret.yaml`. If you skip this, the relay auto-generates a token on first boot — check the logs to find it: `kubectl -n prism logs statefulset/prism-relay | grep "REGISTRATION TOKEN"`
3. Edit `ingress.yaml` with your domain and TLS configuration.
4. Apply all manifests:

```bash
kubectl create namespace prism
kubectl apply -n prism -f .
```

5. Verify:

```bash
kubectl -n prism get pods
kubectl -n prism logs statefulset/prism-relay
curl https://sync.example.com/health
```

## Important notes

- **Single replica only.** The relay uses SQLite, which is single-writer. Do not set `replicas` > 1. The StatefulSet with `OrderedReady` policy ensures safe rolling updates by fully terminating the old pod before starting the new one.
- **WebSocket support required.** Your ingress controller must support WebSocket connections. The `ingress.yaml` includes annotations for nginx-ingress; uncomment the traefik block if using traefik.
- **Registration token.** The relay auto-generates a token on first boot and logs it. To use your own, set `REGISTRATION_TOKEN` in `secret.yaml`. See the [self-hosting docs](https://prismplural.com/docs/self-hosting/) for details.
- **Storage.** The PVC defaults to 1Gi. The relay stays small for typical use — SQLite prunes delivered data automatically.

## Resource requirements

The default resource limits (128Mi-512Mi RAM, 100m-500m CPU) work for most deployments including Raspberry Pi clusters. For larger deployments (100+ concurrent devices), increase the memory limit to 1Gi.

For the full self-hosting guide, see [prismplural.com/docs/self-hosting/](https://prismplural.com/docs/self-hosting/).
