FROM docker.elastic.co/logstash/logstash:8.14.3

ARG http_proxy
ARG https_proxy
ENV http_proxy=${http_proxy} https_proxy=${https_proxy}

# install from the gem you moved into ./plugins/
ARG PLUGIN_GEM=logstash-output-opensearch-2.0.3-java.gem
COPY plugins/${PLUGIN_GEM} /tmp/${PLUGIN_GEM}
RUN logstash-plugin install --no-verify /tmp/${PLUGIN_GEM}

# (optional) copy your pipeline if you keep it alongside
# COPY winlogbeat.conf /usr/share/logstash/pipeline/logstash.conf
