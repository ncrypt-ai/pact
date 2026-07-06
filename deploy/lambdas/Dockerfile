FROM public.ecr.aws/lambda/python:3.12

COPY pyproject.toml README.md LICENSE NOTICE uv.lock ${LAMBDA_TASK_ROOT}/
COPY src ${LAMBDA_TASK_ROOT}/src
# Build docs/_build/html before building the image so /pact/docs is available.
COPY docs/_build/html ${LAMBDA_TASK_ROOT}/docs/_build/html

RUN python -m pip install --upgrade pip setuptools wheel && \
    pip install \
        --extra-index-url https://download.pytorch.org/whl/cpu \
        --only-binary=pillow,c2pa-python,torch,torchvision \
        "${LAMBDA_TASK_ROOT}[all]"

CMD ["pact.server.lambda_app.lambda_handler"]
