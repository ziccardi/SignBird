.PHONY: check dev dev-down dev-logs

check:
	$(MAKE) -C api-service check
	$(MAKE) -C key-certificate-service check
	$(MAKE) -C signature-activation-service check
	$(MAKE) -C document-signing-service check
	$(MAKE) -C web-portal check

dev:
	docker compose up -d --wait --wait-timeout 300
	@echo "SignBird portal available at http://127.0.0.1:5173/"

dev-down:
	docker compose down

dev-logs:
	docker compose logs -f
