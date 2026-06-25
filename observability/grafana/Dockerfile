FROM grafana/grafana:latest

# Copy provisioning config into image
COPY provisioning/dashboards/dashboards.yml /etc/grafana/provisioning/dashboards/dashboards.yml
COPY dashboards/secopsai.json /var/lib/grafana/dashboards/secopsai.json

# Set permissions
USER root
RUN chmod 644 /etc/grafana/provisioning/dashboards/dashboards.yml && \
    chmod 644 /var/lib/grafana/dashboards/secopsai.json
USER grafana
