FROM alpine:latest

COPY ./vault-auditor /bin/vault-auditor
RUN chmod 777 /bin/vault-auditor

ENTRYPOINT [ "/bin/vault-auditor" ]