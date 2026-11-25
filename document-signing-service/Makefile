.PHONY: run build test check

run:
	umask 077 && mvn spring-boot:run

build:
	mvn -DskipTests package

test:
	mvn test

check:
	mvn verify
