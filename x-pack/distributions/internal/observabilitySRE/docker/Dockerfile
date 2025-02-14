# Start from the FIPS-compliant base image
FROM docker.elastic.co/wolfi/chainguard-base-fips:latest

# Install OpenJDK 21
RUN apk add --no-cache \
    openjdk-21 \
    bash \
    git \
    curl \
    make

# Create directory for security configuration
RUN mkdir -p /etc/java/security
RUN mkdir -p /root/.gradle

# Copy configuration files
COPY x-pack/distributions/internal/observabilitySRE/config/security/java.security /etc/java/security/
COPY x-pack/distributions/internal/observabilitySRE/config/security/java.policy /etc/java/security/

# Set environment variables
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk
ENV PATH="${JAVA_HOME}/bin:${PATH}"

# Create working directory
WORKDIR /logstash

# Copy the local Logstash source
COPY . .

# Initial build using JKS truststore
RUN ./gradlew clean bootstrap assemble installDefaultGems

# Convert JKS to BCFKS for truststore and keystore
RUN keytool -importkeystore \
    -srckeystore $JAVA_HOME/lib/security/cacerts \
    -destkeystore /etc/java/security/cacerts.bcfks \
    -srcstoretype jks \
    -deststoretype bcfks \
    -providerpath /logstash/logstash-core/lib/jars/bc-fips-2.0.0.jar \
    -provider org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider \
    -deststorepass changeit \
    -srcstorepass changeit \
    -noprompt

RUN keytool -importkeystore \
    -srckeystore $JAVA_HOME/lib/security/cacerts \
    -destkeystore /etc/java/security/keystore.bcfks \
    -srcstoretype jks \
    -deststoretype bcfks \
    -providerpath /logstash/logstash-core/lib/jars/bc-fips-2.0.0.jar \
    -provider org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider \
    -deststorepass changeit \
    -srcstorepass changeit \
    -noprompt

ENV JAVA_SECURITY_PROPERTIES=/etc/java/security/java.security
ENV LS_JAVA_OPTS="\
    -Dio.netty.ssl.provider=JDK \
    # Enable debug logging for ensuring BCFIPS is being used if needed
    # -Djava.security.debug=ssl,provider,certpath \
    -Djava.security.properties=${JAVA_SECURITY_PROPERTIES} \
    -Djavax.net.ssl.keyStore=/etc/java/security/keystore.bcfks \
    -Djavax.net.ssl.keyStoreType=BCFKS \
    -Djavax.net.ssl.keyStoreProvider=BCFIPS \
    -Djavax.net.ssl.keyStorePassword=changeit \
    -Djavax.net.ssl.trustStore=/etc/java/security/cacerts.bcfks \
    -Djavax.net.ssl.trustStoreType=BCFKS \
    -Djavax.net.ssl.trustStoreProvider=BCFIPS \
    -Djavax.net.ssl.trustStorePassword=changeit \
    -Dssl.KeyManagerFactory.algorithm=PKIX \
    -Dssl.TrustManagerFactory.algorithm=PKIX \
    -Dorg.bouncycastle.fips.approved_only=true"

# Example test run, most use cases will override this
CMD ["./gradlew", "--info", "--stacktrace", "-PrunTestsInFIPSMode=true", "runIntegrationTests"]