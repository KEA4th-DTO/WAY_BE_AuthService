FROM openjdk:17-alpine
COPY build/libs/way.auth-0.0.1-SNAPSHOT.jar app.jar
COPY --from=docker.elastic.co/observability/apm-agent-java:latest /usr/agent/elastic-apm-agent.jar elastic-apm-agent.jar
ENTRYPOINT ["java", "-javaagent:elastic-apm-agent.jar", "-Delastic.apm.service_name=way-auth", "-Delastic.apm.secret_token=R7oE1azzuor1YXL1qu", "-Delastic.apm.server_url=https://b750d80f08ce49918f2047785ba4021e.apm.us-west-2.aws.cloud.es.io:443", "-Delastic.apm.environment=my-environment", "-Delastic.apm.application_packages=org.example", "-jar", "app.jar"]
EXPOSE 8080