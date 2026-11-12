FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /opt/defnett
COPY app.py agent.py collector.py remediator.py executor.py \
     db.py policy_gate.py approvals.py operator_auth.py trajectory.py risk_engine.py modbus_lab.py \
     approval_authority.py authority_client.py tls_support.py \
     provision_operators.py provision_master.py /opt/defnett/
COPY dashboard/ /opt/defnett/dashboard/
COPY ot-policy.json /opt/defnett/ot-policy.json

RUN groupadd --gid 10001 defnett \
    && useradd --uid 10001 --gid defnett --create-home --no-log-init defnett \
    && chmod 0644 /opt/defnett/*.py /opt/defnett/dashboard/* \
    && install -d -o 10001 -g 10001 -m 0700 /data /state /evidence /target /quarantine /master /manifest /ops /approval

USER 10001:10001
EXPOSE 8080 8090 8091 8092
ENTRYPOINT ["python"]
