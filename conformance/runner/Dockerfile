# The conformance suite's CI runner, scripts/run-test-plan.py, with the two
# modules it imports, at the commit that release-v5.3.4 tags. Each file is
# verified against its sha256, and each Python package, with every one of
# its dependencies, against the hash in requirements.txt.
#
# The base image is pinned by tag and digest, and bumped by hand with a
# changelog entry in docs/harness.md, as the suite's own images are.

FROM python:3.13.18-slim-trixie@sha256:09a17cad02668ae61ece136b4fd36ac3849e14f670ebedb637ea3e15580525bc

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes --only-binary :all: -r /tmp/requirements.txt

ARG SUITE_SCRIPTS=https://gitlab.com/openid/conformance-suite/-/raw/23353b36957d6466010de767c812d2c91ed37638/scripts
ADD --checksum=sha256:6043f8fb9d64dcd30235540cae1f32eb4e94618d1fc5408f1e8ae626d6553ad2 ${SUITE_SCRIPTS}/run-test-plan.py /suite/
ADD --checksum=sha256:660214cc6ca9b3c09297f61908a575db7b1552e8f44eecd5740d1c27fa2cfca8 ${SUITE_SCRIPTS}/conformance.py /suite/
ADD --checksum=sha256:2b00870b2dc46f1d44d047c715c0ef6978f24ece97a4a9d3b48ceeea8d01830f ${SUITE_SCRIPTS}/test_plan_parser.py /suite/
# The runner reads every file in certs-keys/ beside it, to substitute into
# configurations that name them; pulsar's names none, so it stays empty.
# Everything is made readable by any user: the container runs as whoever
# runs make conformance, and without this they could not read what ADD
# fetched, even with ADD --chmod=644.
RUN mkdir /suite/certs-keys && chmod -R a+rX /suite

COPY --chmod=755 run.sh /run.sh
ENTRYPOINT ["/run.sh"]
