FROM alpine:3.9

RUN apk --update --no-cache add python3 bash curl git
RUN pip3 install --upgrade pip
RUN pip install awscli ansi2html boto3
RUN git clone https://github.com/toniblyx/prowler/

ENTRYPOINT ["/prowler/prowler"]
CMD []