FROM ubuntu:20.04

ARG VERSION
ARG VCS_REF
ARG BUILD_DATE

COPY able /usr/local/bin/

RUN set -xe && \
    chmod +x /usr/local/bin/able

ENTRYPOINT ["/usr/local/bin/able"]
CMD []

LABEL maintainer=mselby@tokenranin.net \
      org.label-schema.schema-version=1.0 \
      org.label-schema.version=$VERSION \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.build-date=$BUILD_DATE
