FROM ubuntu:22.04@sha256:3d1556a8a18cf5307b121e0a98e93f1ddf1f3f8e092f1fddfd941254785b95d7

ENV user chall
ENV chall_port 31337

RUN apt-get update
RUN apt-get -y install socat

RUN adduser -u 1337 $user

ADD ./deploy/flag /home/$user/flag
ADD ./deploy/$user /home/$user/$user
ADD ./deploy/run.sh /home/$user/run.sh
ADD ./deploy/loop.sh /home/$user/loop.sh

RUN chown root:$user /home/$user/flag
RUN chown root:$user /home/$user/$user
RUN chown root:$user /home/$user/run.sh
RUN chown root:$user /home/$user/loop.sh

RUN chmod 755 /home/$user/$user
RUN chmod 440 /home/$user/flag
RUN chmod 755 /home/$user/run.sh
RUN chmod 755 /home/$user/loop.sh

WORKDIR /home/$user
USER $user
EXPOSE $chall_port
CMD ["/home/chall/loop.sh"]
