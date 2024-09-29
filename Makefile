.PHONY: run wasm web-dev

lint-and-fmt-web:
	cd web && \
		yarn tsc && \
		prettier --write .

test-rust:
	cargo test

build-server: test-rust
	docker build -t registry.k8s.ojdip.net/compost-server -f Dockerfile.server .

build-web: lint-and-fmt-web
	docker build -t registry.k8s.ojdip.net/compost-web -f Dockerfile.web .

build: build-server build-web

push: build
	docker push registry.k8s.ojdip.net/compost-server
	docker push registry.k8s.ojdip.net/compost-web

deploy: push
	kubectl -n compost rollout restart deployment/compost-server
	kubectl -n compost rollout restart deployment/compost-web

wasm:
	cd crypto && \
		wasm-pack build --release --weak-refs

web-dev: wasm
	cd web && \
		rm -rf node_modules && \
		yarn && \
		yarn dev

populate:
	./tools/populate.sh

recreate:
	AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE \
	AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
	aws s3api delete-bucket --bucket compost --endpoint-url http://localhost:9444 || true
	AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE \
	AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
	aws s3api create-bucket --bucket compost --endpoint-url http://localhost:9444


run:
	LOG_LEVEL=info \
	AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE \
	AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
	cargo run -- \
		--smtp-bind [::]:1025 \
		--api-bind [::]:1080 \
		--smtp-tls-cert tools/localhost.crt \
		--smtp-tls-key tools/localhost.key \
		--bucket-endpoint http://localhost:9444 \
		--bucket-name compost \
		--bucket-region local \
		--prometheus

run-aws:
	LOG_LEVEL=info \
	cargo run -- \
		--smtp-bind [::]:1025 \
		--api-bind [::]:1080 \
		--smtp-tls-cert tools/localhost.crt \
		--smtp-tls-key tools/localhost.key \
		--bucket-name compost-email \
		--bucket-region eu-west-1 \
		--prometheus

run-haproxy:
	docker run \
		-v $(PWD)/tools/:/usr/local/etc/haproxy/ \
		--rm \
		--network=host \
		haproxy:latest
