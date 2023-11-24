FROM openjdk:17-jdk
WORKDIR /app

COPY target/authentication-service-0.0.1-SNAPSHOT.jar /app/authentication-service-0.0.1.jar

EXPOSE 5555

CMD ["java", "-jar", "authentication-service-0.0.1.jar"]