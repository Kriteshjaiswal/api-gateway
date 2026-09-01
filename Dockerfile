FROM eclipse-temurin:21-jdk-alpine AS builder

WORKDIR /app

# Install Maven
RUN apk add --no-cache maven

# Copy API Gateway project
COPY apigateway/pom.xml .
COPY apigateway/src ./src

# Build application
RUN mvn clean package -DskipTests

# Runtime image
FROM eclipse-temurin:21-jre-alpine

WORKDIR /app

# Copy generated JAR
COPY --from=builder /app/target/*.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]