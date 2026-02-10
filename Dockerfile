FROM aquasec/trivy:0.69.1 AS trivy

FROM alpine:3

RUN apk update && apk upgrade && apk --no-cache add bash coreutils curl file gnupg jq skopeo tar sqlite unzip util-linux yara yq \
  && GRYPE_VERSION="0.107.1" \
  && curl -sSL "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz" -o grype.tar.gz \
  && tar -xzf grype.tar.gz -C /usr/local/bin grype \
  && rm grype.tar.gz

COPY --from=trivy /contrib /contrib
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

RUN addgroup -g 65532 -S nonroot \
  && adduser -u 65532 -S nonroot -G nonroot -s /bin/sh

WORKDIR /home/nonroot

COPY check-exclusions.sh \
  grype.tmpl \
  mime-helper.sh \
  scan.sh \
  scan-date.sh \
  scan-download-unpack.sh \
  scan-epss.sh \
  scan-grype.sh \
  scan-inthewild-io.sh \
  scan-misconfig.sh \
  scan-new-tags.sh \
  scan-trivy.sh \
  scan-virustotal.sh \
  scan-vulners-com.sh \
  scan-vulnerabilities.sh \
  scan-yara.sh \
  trivy.tmpl \
  ./

RUN chown -R 65532:65532 *.sh && \
  chmod 555 /home/nonroot && \
  chmod 755 /home/nonroot/*.sh

USER nonroot
