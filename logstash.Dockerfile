FROM docker.elastic.co/logstash/logstash:8.14.3

# optional: proxy support if you need it later
ARG http_proxy
ARG https_proxy
ENV http_proxy=${http_proxy} https_proxy=${https_proxy}

# copy the gem you downloaded on the host (same folder as this Dockerfile)
COPY logstash-output-opensearch-*.gem /tmp/

# avoid any network verification / dependency lookups
RUN logstash-plugin install --no-verify /tmp/logstash-output-opensearch-*.gem

