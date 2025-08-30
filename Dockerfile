FROM amazoncorretto:17-alpine-jdk

EXPOSE 8080

ADD target/demodocker.jar demodocker.jar

# RUN THE APP
ENTRYPOINT ["java", "-jar", "/demodocker.jar"]