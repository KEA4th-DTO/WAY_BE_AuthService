FROM openjdk:17-alpine
# COPY gradlew ./
# COPY gradle/ ./gradle/
# RUN ./gradlew build
COPY build/libs/way.auth-0.0.1-SNAPSHOT.jar app.jar
CMD ["java", "-jar", "app.jar"]
EXPOSE 8080