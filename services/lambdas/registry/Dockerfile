FROM public.ecr.aws/lambda/python:3.11

COPY pyproject.toml README.md LICENSE NOTICE uv.lock ${LAMBDA_TASK_ROOT}/
COPY src ${LAMBDA_TASK_ROOT}/src

RUN pip install "${LAMBDA_TASK_ROOT}[aws]"

CMD ["pact.server.lambda_app.lambda_handler"]
