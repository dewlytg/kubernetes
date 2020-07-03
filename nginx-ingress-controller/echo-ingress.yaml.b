apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: echo-ingress
  namespace: default
  annotations:
    kubernetes.io/ingress.class: nginx
spec:
  rules:
  - host: echo.com
    http:
      paths:
      - path: /
        backend:
          serviceName: echo
          servicePort: 8080
