apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-nginx
  namespace: nginx
spec:
  replicas: 1
  replicas: 1
  selector:
    matchLabels:
      run: my-nginx
  template:
    metadata:
      labels:
        run: my-nginx
    spec:
      containers:
      - name: my-nginx
        image: nginx
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: my-nginx
  namespace: nginx
  labels:
    app: my-nginx
spec:
  ports:
  - port: 80
    protocol: TCP
    name: http
  selector:
    run: my-nginx
---
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: nginx-service-ingress                 
  namespace: nginx
  annotations:
    kubernetes.io/ingress.class: "nginx"
    cert-manager.io/cluster-issuer: "letsencrypt-staging"
spec:
  tls:
  - hosts:
    - nginx.xtestx.tech
    secretName: nginx-tls
  rules:
  - host: nginx.xtestx.tech
    http:
      paths:
      - backend:
          serviceName: my-nginx
          servicePort: 80
        path: /
---
apiVersion: cert-manager.io/v1alpha2
kind: Issuer
metadata:
  name: letsencrypt-prod
  namespace: nginx
spec:
  selfSigned: {}
---
apiVersion: cert-manager.io/v1alpha2
kind: Certificate
metadata:
  name: nginx-tls
  namespace: nginx
spec:
  secretName: nginx-tls
  duration: 2160h
  renewBefore: 360h
  dnsNames:
  - nginx.xtestx.tech
  issuerRef:
    name: letsencrypt-prod
