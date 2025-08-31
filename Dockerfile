FROM amazoncorretto:17-alpine-jdk

EXPOSE 8080

ADD target/notesappdocker.jar notesappdocker.jar

# RUN THE APP
ENTRYPOINT ["java", "-jar", "/notesappdocker.jar"]